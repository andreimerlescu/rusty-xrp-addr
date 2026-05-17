use std::collections::HashSet;
use std::io::{self, Write};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use regex::RegexBuilder;
use ripple_keypairs::{Algorithm, Entropy, Seed};
use terminal_size::terminal_size;

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser, Debug)]
#[command(
    name = "find-xrp-addr",
    version = "1.0.1",
    about = "XRP Ledger vanity address finder. Uses multiple CPU cores to search for rAddresses matching --find, --begins, or --ends criteria.",
    long_about = "A high-performance vanity XRP address generator. Supports ED25519 (recommended) and SECP256K1. Optionally saves found wallets to 1Password vault using the `op` CLI."
)]
struct Cli {
    /// Desired substring to appear in the rAddress (e.g. "abc")
    #[arg(long, env = "FIND", help = "desired find to appear in rAddress")]
    find: Option<String>,

    /// Ignore case when matching --find (default true)
    #[arg(long, default_value_t = true, env = "INSENSITIVE", help = "ignore case sensitivity for --find")]
    insensitive: bool,

    /// Cryptographic algorithm: ed25519 (default, recommended) or secp256k1
    #[arg(long, default_value = "ed25519", env = "ALGORITHM", help = "ed25519 or secp256k1")]
    algorithm: String,

    /// rAddress must begin with r + this prefix (do not include leading 'r')
    #[arg(long, env = "BEGINS", help = "prefix after 'r' for rAddress to begin with")]
    begins: Option<String>,

    /// rAddress must end with this suffix
    #[arg(long, env = "ENDS", help = "suffix for rAddress to end with")]
    ends: Option<String>,

    /// Number of CPU cores/threads to use (0 = all available)
    #[arg(long, default_value_t = 0, env = "CORES", help = "number of processors to use (0 = max)")]
    cores: usize,

    /// Use 1Password to store found wallets (requires `op` CLI installed and authenticated)
    #[arg(long = "1p", env = "USE_ONEPASSWORD", action = clap::ArgAction::SetTrue, help = "save found wallets to 1Password vault")]
    onep: bool,

    /// 1Password vault name to use when --1p is enabled
    #[arg(long, default_value = "XRPL", env = "VAULT", help = "1Password vault name")]
    vault: String,

    /// Optional path to config file (CONFIG env var). Basic existence check only; CLI flags take precedence.
    #[arg(long, env = "CONFIG", help = "path to optional config file (existence checked)")]
    config: Option<String>,
}

#[derive(Clone)]
struct Trial {
    seed: String,
    address: String,
}

#[derive(Clone)]
enum Matcher {
    Contains(String),
    Regex(regex::Regex),
}

impl Matcher {
    fn matches(&self, s: &str) -> bool {
        match self {
            Matcher::Contains(sub) => s.contains(sub),
            Matcher::Regex(re) => re.is_match(s),
        }
    }
}

struct AppConfig {
    algorithm: Algorithm,
    begins: String,
    ends: String,
    find_len: usize,
    onep: bool,
    vault: String,
    found: Option<Arc<RwLock<HashSet<String>>>>,
}

fn format_with_commas(n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn get_terminal_width() -> usize {
    terminal_size()
        .map(|(w, _)| w.0 as usize)
        .unwrap_or(80)
}

fn validate_chars(s: &str, field: &str, insensitive: bool) {
    if s.is_empty() {
        return;
    }
    let alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
    let check_s = if insensitive {
        s.to_lowercase()
    } else {
        s.to_string()
    };
    let check_alph = if insensitive {
        alphabet.to_lowercase()
    } else {
        alphabet.to_string()
    };
    for c in check_s.chars() {
        if !check_alph.contains(c) {
            eprintln!("Error: cannot use '{}' in --{}", c, field);
            std::process::exit(1);
        }
    }
}

fn is_alphanumeric(s: &str) -> bool {
    s.chars().all(|c| c.is_alphanumeric())
}

fn prevent_confusing_chars(find: &str, begins: &str, ends: &str) {
    let prevent = ["I", "O", "l", "0"];
    for p in &prevent {
        if find.contains(p) || begins.contains(p) || ends.contains(p) {
            eprintln!("Error: cannot use confusing character '{}' in --find, --begins or --ends (avoid I, O, l, 0)", p);
            std::process::exit(1);
        }
    }
}

fn search(
    tx: mpsc::Sender<Trial>,
    matcher: Arc<Matcher>,
    config: Arc<AppConfig>,
    count: Arc<AtomicU64>,
) {
    loop {
        if !RUNNING.load(Ordering::Relaxed) {
            break;
        }

        let seed = Seed::new(Entropy::Random, &config.algorithm);
        let seed_str = seed.to_string();

        let derive_result = seed.derive_keypair();
        let (_, public_key) = match derive_result {
            Ok(kp) => kp,
            Err(_) => continue, // rare, retry
        };

        let address = public_key.derive_address();

        count.fetch_add(1, Ordering::Relaxed);

        if config.onep {
            if let Some(ref found_lock) = config.found {
                let guard = found_lock.read().unwrap();
                if guard.contains(&address) {
                    continue;
                }
            }
        }

        let match_begins = config.begins.is_empty()
            || address.starts_with(&format!("r{}", config.begins));
        let match_ends = config.ends.is_empty() || address.ends_with(&config.ends);
        let match_find = config.find_len == 0 || matcher.matches(&address);

        if match_begins && match_ends && match_find {
            let _ = tx.send(Trial {
                seed: seed_str,
                address,
            });
        }
    }
}

fn add_to_onepassword(trial: &Trial, num: u64, vault: &str) {
    let address = &trial.address;
    let seed = &trial.seed;

    // Build op CLI command. Adjust field syntax if your `op` version differs.
    // This creates a Crypto Wallet item with address (text) and seed (concealed) in a "Wallet" section.
    let mut cmd = Command::new("op");
    cmd.args([
        "item",
        "create",
        "--title",
        address,
        "--vault",
        vault,
        "--category",
        "Crypto Wallet",
        &format!("address[text]={}", address),
        &format!("seed[concealed,section=Wallet]={}", seed),
        "--format",
        "json",
    ]);

    match cmd.output() {
        Ok(output) => {
            if output.status.success() {
                let id = if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    json_val["id"].as_str().unwrap_or("unknown").to_string()
                } else {
                    "unknown".to_string()
                };
                println!(
                    "\nFOUND XRP WALLET - scanned {} seeds - Added ID {} to 1Password vault '{}'!",
                    format_with_commas(num),
                    id,
                    vault
                );
            } else {
                eprintln!(
                    "Failed to create 1Password item: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => {
            eprintln!("Failed to execute `op` command (is 1Password CLI installed and in PATH?): {}", e);
        }
    }
}

fn main() {
    // Check CONFIG env for existence (maintains checkfs-like protection)
    if let Ok(config_path) = std::env::var("CONFIG") {
        if !std::path::Path::new(&config_path).exists() {
            eprintln!("Note: CONFIG file '{}' does not exist. Proceeding with CLI flags/env vars.", config_path);
        } else {
            // Config file parsing from JSON/YAML/INI is not implemented in this Rust version.
            // CLI flags and environment variables take full precedence.
            // You can still use the file for documentation or future extension.
        }
    }

    let cli = Cli::parse();

    // Check for `op` binary if user requested -1p. If missing, disable 1p and only print to STDOUT.
    let use_onep = if cli.onep {
        if Command::new("op").arg("--version").output().is_err() {
            eprintln!("1password is not installed on the system - skipping -1p flag");
            false
        } else {
            true
        }
    } else {
        false
    };

    if cli.find.is_none() && cli.begins.is_none() && cli.ends.is_none() {
        // clap version flag is handled automatically, but we can exit early if needed
    }

    let find = cli.find.clone().unwrap_or_default();
    let begins = cli.begins.clone().unwrap_or_default();
    let ends = cli.ends.clone().unwrap_or_default();

    if find.is_empty() && begins.is_empty() && ends.is_empty() {
        eprintln!("Error: Missing --find, --begins or --ends. At least one is required.");
        std::process::exit(1);
    }

    prevent_confusing_chars(&find, &begins, &ends);

    if !find.is_empty() && !is_alphanumeric(&find) {
        eprintln!("Error: --find must be alphanumeric.");
        std::process::exit(1);
    }

    let insensitive = cli.insensitive;
    validate_chars(&find, "find", insensitive);
    validate_chars(&begins, "begins", insensitive);
    validate_chars(&ends, "ends", insensitive);

    // Determine algorithm
    let alg_str = cli.algorithm.to_lowercase();
    let algorithm = if alg_str == "ed25519" || alg_str.contains("ed") {
        Algorithm::Ed25519
    } else if alg_str == "secp256k1" || alg_str.contains("secp") {
        Algorithm::Secp256k1
    } else {
        eprintln!("Error: invalid algorithm '{}'. Use ed25519 or secp256k1.", cli.algorithm);
        std::process::exit(1);
    };

    // Create matcher
    let find_len = find.len();
    let matcher = if find_len == 0 {
        Matcher::Contains(String::new())
    } else if insensitive {
        let escaped = regex::escape(&find);
        let re = RegexBuilder::new(&escaped)
            .case_insensitive(true)
            .build()
            .expect("Failed to compile case-insensitive regex");
        Matcher::Regex(re)
    } else {
        Matcher::Contains(find.clone())
    };

    // Print search mode
    let cores_available = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    let cores = if cli.cores > 0 && cli.cores < cores_available {
        cli.cores
    } else {
        cores_available
    };

    if find_len > 0 && begins.is_empty() && ends.is_empty() {
        println!(
            "Searching for r...{}... with {}/{} processors.",
            find, cores, cores_available
        );
    } else if find_len == 0 && !begins.is_empty() && ends.is_empty() {
        println!(
            "Searching for r{}... with {}/{} processors.",
            begins, cores, cores_available
        );
    } else if find_len == 0 && begins.is_empty() && !ends.is_empty() {
        println!(
            "Searching for r...{} with {}/{} processors.",
            ends, cores, cores_available
        );
    } else if find_len > 0 && !begins.is_empty() && ends.is_empty() {
        println!(
            "Searching for r{}...{}... with {}/{} processors.",
            begins, find, cores, cores_available
        );
    } else if find_len > 0 && begins.is_empty() && !ends.is_empty() {
        println!(
            "Searching for r...{}...{} with {}/{} processors.",
            find, ends, cores, cores_available
        );
    } else if find_len == 0 && !begins.is_empty() && !ends.is_empty() {
        println!(
            "Searching for r{}...{} with {}/{} processors.",
            begins, ends, cores, cores_available
        );
    } else if find_len > 0 && !begins.is_empty() && !ends.is_empty() {
        println!(
            "Searching for r{}...{}...{} with {}/{} processors.",
            begins, find, ends, cores, cores_available
        );
    } else {
        eprintln!("Unsupported combination of parameters.");
        std::process::exit(1);
    }

    // Setup 1Password found set if needed (no preloading of existing vault items - matches Go default behavior of not touching existing items)
    let found_set: Option<Arc<RwLock<HashSet<String>>>> = if use_onep {
        Some(Arc::new(RwLock::new(HashSet::new())))
    } else {
        None
    };

    let app_config = Arc::new(AppConfig {
        algorithm,
        begins,
        ends,
        find_len,
        onep: use_onep,
        vault: cli.vault.clone(),
        found: found_set,
    });

    // Channel for found trials
    let (tx, rx) = mpsc::channel::<Trial>();

    let count = Arc::new(AtomicU64::new(0));

    // Spawn worker threads
    for _ in 0..cores {
        let tx = tx.clone();
        let matcher = Arc::new(matcher.clone());
        let config = Arc::clone(&app_config);
        let count = Arc::clone(&count);
        thread::spawn(move || {
            search(tx, matcher, config, count);
        });
    }

    // Signal handler
    ctrlc::set_handler(|| {
        RUNNING.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let start = Arc::new(Instant::now());
    let count_for_status = Arc::clone(&count);
    let start_for_status = Arc::clone(&start);

    // Status printing thread
    thread::spawn(move || {
        loop {
            if !RUNNING.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
            let num = count_for_status.load(Ordering::Relaxed);
            let elapsed = start_for_status.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                let rate = (num as f64 / elapsed).floor() as u64;
                let num_str = format_with_commas(num);
                let rate_str = format_with_commas(rate);
                let prefix = format!("Tested: {} seeds at {}/sec", num_str, rate_str);
                let width = get_terminal_width();
                let spaces_len = if width > prefix.len() + 2 {
                    width - prefix.len() - 2
                } else {
                    0
                };
                let spaces = " ".repeat(spaces_len);
                print!("\r{}{}", prefix, spaces);
                let _ = io::stdout().flush();
            }
        }
    });

    // Main receive loop
    let mut final_printed = false;
    loop {
        if !RUNNING.load(Ordering::Relaxed) && !final_printed {
            let num = count.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                num as f64 / elapsed
            } else {
                0.0
            };
            println!(
                "\nTested: {} seeds at {:.2}/sec",
                format_with_commas(num),
                rate
            );
            final_printed = true;
            break;
        }

        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(trial) => {
                let num = count.load(Ordering::Relaxed);
                if use_onep {
                    if let Some(ref fset) = app_config.found {
                        let mut guard = fset.write().unwrap();
                        guard.insert(trial.address.clone());
                    }
                    let vault = cli.vault.clone();
                    let trial_for_thread = trial.clone();
                    thread::spawn(move || {
                        add_to_onepassword(&trial_for_thread, num, &vault);
                    });
                } else {
                    println!(
                        "\n{:3}: Found {} ( family seed: {} )",
                        num, trial.address, trial.seed
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Status thread handles periodic updates; continue to check RUNNING
                if !RUNNING.load(Ordering::Relaxed) && !final_printed {
                    // will be handled at top of loop
                }
                continue;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !final_printed {
                    let num = count.load(Ordering::Relaxed);
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = if elapsed > 0.0 { num as f64 / elapsed } else { 0.0 };
                    println!(
                        "\nTested: {} seeds at {:.2}/sec (channel closed)",
                        format_with_commas(num),
                        rate
                    );
                    final_printed = true;
                }
                break;
            }
        }
    }

    // Ensure clean exit
    RUNNING.store(false, Ordering::SeqCst);
    // Give status thread a moment to stop
    thread::sleep(Duration::from_millis(100));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_with_commas() {
        assert_eq!(format_with_commas(0), "0");
        assert_eq!(format_with_commas(123), "123");
        assert_eq!(format_with_commas(1234), "1,234");
        assert_eq!(format_with_commas(1234567), "1,234,567");
        assert_eq!(format_with_commas(1000000000), "1,000,000,000");
    }

    #[test]
    fn test_is_alphanumeric() {
        assert!(is_alphanumeric("abc123"));
        assert!(is_alphanumeric("Test"));
        assert!(!is_alphanumeric("abc-123"));
        assert!(!is_alphanumeric("hello world"));
        assert!(is_alphanumeric(""));
    }

    #[test]
    fn test_matcher_contains() {
        let m = Matcher::Contains("test".to_string());
        assert!(m.matches("rTestAddress"));
        assert!(m.matches("somethingtestelse"));
        assert!(!m.matches("no match here"));
    }

    #[test]
    fn test_matcher_regex_case_insensitive() {
        let escaped = regex::escape("Test");
        let re = RegexBuilder::new(&escaped)
            .case_insensitive(true)
            .build()
            .unwrap();
        let m = Matcher::Regex(re);
        assert!(m.matches("rtestaddress"));
        assert!(m.matches("rTEST123"));
        assert!(!m.matches("no match"));
    }

    #[test]
    fn test_prevent_confusing_chars_does_not_panic_on_clean_input() {
        // This should not call exit(1)
        prevent_confusing_chars("abc", "def", "123");
        prevent_confusing_chars("", "", "");
    }

    // Note: validate_chars and prevent_confusing_chars call std::process::exit on bad input.
    // They are integration-level guards. The pure logic (alphabet check) is covered indirectly
    // by the fact that the app starts successfully with valid inputs.
}
