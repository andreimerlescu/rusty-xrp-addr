# find-xrp-addr

High-performance XRP Ledger vanity address finder written in Rust.

Searches for custom r... addresses matching a substring (--find), prefix (--begins), suffix (--ends), or any combination, using all available CPU cores.

## Features

- Multi-threaded (configurable cores)
- ED25519 (default, recommended) and secp256k1 support
- Case-insensitive or sensitive matching
- Optional saving to 1Password via op CLI (--1p)
- Live progress (seeds tested + rate/sec)
- Graceful shutdown on Ctrl-C
- Validates against XRPL alphabet and prevents confusing characters (I, O, l, 0)

## Getting Started / Compilation

### Prerequisites

- Rust toolchain (stable) - install from https://rustup.rs
- For --1p: 1Password CLI (op) installed and authenticated

### Build

    make build

Or manually:

    cargo build --release

The release binary will be at bin/find-xrp-addr (after make build).

### Run

    make run ARGS="--find test --cores 8"

Or directly:

    ./bin/find-xrp-addr --find "abc" --insensitive

**Common examples**:

- Search containing "test": ./bin/find-xrp-addr --find test
- Begins with "abc" after r: ./bin/find-xrp-addr --begins abc
- Ends with "xyz": ./bin/find-xrp-addr --ends xyz
- Combined + save to 1Password: ./bin/find-xrp-addr --begins abc --find test --1p --vault XRPL
- Limit cores: --cores 4

Use make run ARGS="..." for convenience.

### Makefile Targets

- make build - compile release binary to bin/find-xrp-addr
- make run - build + run (pass args via ARGS="...")
- make test - run unit tests (proves helper functions)
- make clean - clean cargo + remove bin/

## Using the App

The app generates random keypairs (using the ripple-keypairs crate) and derives classic r addresses until a match is found.

When a match is found:
- Without --1p: Prints to STDOUT with the address and family seed.
- With --1p (and op available): Creates a Crypto Wallet item in the specified vault with address and concealed seed fields.

**Important**: Family seeds are extremely sensitive. Protect them. When using --1p they are stored as concealed fields.

## Gotchas & Security Notes

1. **1Password (op CLI)**:

   If --1p / -1p is used but op is not installed or not in PATH, the app prints:

       1password is not installed on the system - skipping -1p flag

   It then falls back to printing matches to STDOUT only. No attempt is made to use 1Password.

   We do not read or modify any existing items in your vault (no preloading). This matches the default behavior of the original Go binary.

2. **Search Time**:

   Vanity searches can take a very long time (seconds to days) depending on pattern length and rarity.
   Short patterns or common letters finish faster. Long/complex patterns may never finish in reasonable time.
   Use specific but realistic patterns.

3. **No Config File Parsing**:

   The CONFIG environment variable is checked for existence (protection similar to original checkfs).
   Full parsing of .json/.yaml/.ini is not implemented. Use command-line flags or environment variables (clap supports ENV vars for every flag).

4. **Security Considerations** (from code review):

   - All cryptographic operations use the audited ripple-keypairs crate.
   - No shell injection possible - op commands are built with std::process::Command::args().
   - User-provided --find string is properly escaped for regex.
   - Seeds are only ever printed when not using 1Password, or passed as concealed fields.
   - Threading uses proper synchronization (Arc, RwLock, atomics).
   - Fail-fast on invalid startup arguments.
   - Release builds are stripped and optimized.
   - Your responsibility: Once a seed is printed or saved to 1Password, secure it. Never commit seeds to git.

5. **Other**:

   - The binary is placed in bin/ (.keep file keeps the directory in git; compiled binaries are gitignored).
   - GitHub Actions workflow (.github/workflows/test-app.yml) is manually triggered only via the "Run workflow" button. It never runs on push or PRs.
   - Unit tests exist for core helper functions (format_with_commas, is_alphanumeric, Matcher, etc.). Run with make test.

## Project Structure

    find-xrp-addr/
    ├── .github/workflows/test-app.yml   # Manual-dispatch only CI
    ├── bin/
    │   └── .keep
    ├── src/main.rs
    ├── Cargo.toml
    ├── Makefile
    └── README.md

## License

Without written permission by Andrei Merlescu, the repository owner, you cannot use this software for any commercial purposes and nor can you use this source code in any commercial software, including GPL-3 or AGPL-3 (or similar) kind of copyright. 
