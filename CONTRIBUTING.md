# Contributing to ghostroute

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/PwnedBytes0x1/ghostroute
   cd ghostroute
   ```

2. **Build**
   ```bash
   cargo build
   ```

3. **Run tests**
   ```bash
   cargo test
   ```

4. **Lint**
   ```bash
   cargo clippy
   cargo fmt --check
   ```

## Code Style

- Follow Rust 2021 edition idioms
- Run `cargo fmt` before committing
- No unsafe code unless absolutely necessary and documented
- All public items must have doc comments
- Use `eprintln!` for progress/info, `println!` for pipeline output
- Color: `[INF]` green, `[ERR]` red, `[WARN]` yellow, `[DET]` cyan

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes
3. Ensure all tests pass: `cargo test`
4. Ensure no clippy warnings: `cargo clippy`
5. Submit PR with clear description of changes
6. Reference any related issues

## Adding a New Smuggling Variant

1. Create `src/scan/<variant>.rs` with a `pub async fn probe()` that returns `Result<ScanResult, String>`
2. Register the variant in `src/scan/mod.rs` under `run_scan()`
3. Add the variant name to `src/cli.rs` variant help text
4. Add a test case in `tests/`
5. Update README.md variant table

## Commit Messages

Follow conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation
- `refactor:` code refactoring
- `test:` testing
- `chore:` maintenance

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
