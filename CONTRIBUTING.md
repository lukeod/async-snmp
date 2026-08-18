# Contributing to async-snmp

## Set up your development environment

1. Fork and clone the repository.
2. Install Rust 1.88 or later with [rustup](https://rustup.rs/).
3. Install the toolchains and components used by continuous integration:

   ```bash
   rustup toolchain install stable --component clippy
   rustup toolchain install nightly --component rustfmt
   ```

4. Run the default test suite:

   ```bash
   cargo test --locked
   ```

## Format and lint the code

Format code before committing:

```bash
cargo +nightly fmt --all
```

Verify formatting and run Clippy with all features:

```bash
cargo +nightly fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
```

## Run tests

Run the full test suite:

```bash
cargo test --locked --all-features
cargo check --locked --all-features --all-targets
```

Test the AWS-LC FIPS backend without the default RustCrypto backend:

```bash
cargo test --locked --no-default-features --features agent,crypto-fips
```

The cryptographic backend features are additive. The full test suite enables
both providers and tests explicit provider selection.

The interoperability tests require Docker and the local net-snmp test image:

```bash
docker build -t async-snmp-test:latest tests/containers/snmpd/
cargo test --locked --test interop --all-features -- --ignored
```

## Build the documentation

Test, build, and open the documentation:

```bash
cargo test --locked --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
cargo doc --locked --all-features --no-deps --open
```

## Prepare a pull request

- Focus each pull request on one feature or fix.
- Add tests for new functionality and bug fixes.
- Update affected documentation and examples.
- Run the relevant checks before requesting review.
- Follow the existing code style and patterns.

## Report an issue

Include the following information in a bug report:

- Rust version from `rustc --version`.
- Operating system and version.
- Minimal reproduction case.
- Expected and actual behavior.

## License

Contributions use the project's dual MIT or Apache-2.0 license.
