# Contributing to async-snmp

Thank you for your interest in contributing!

## Getting Started

1. Fork and clone the repository
2. Install Rust 1.88 or later via [rustup](https://rustup.rs/)
3. Run the test suite: `cargo test`

## Development

### Code Style

Format code before committing:

```bash
cargo fmt
```

Check for lint issues:

```bash
cargo clippy --all-targets --features agent,crypto-rustcrypto,cli,mib,rt-multi-thread
```

### Testing

Run the full test suite:

```bash
cargo test --features agent,crypto-rustcrypto,cli,mib,rt-multi-thread
```

To test with the FIPS crypto backend (requires aws-lc-rs build dependencies):

```bash
cargo test --no-default-features --features agent,crypto-fips
```

Note: `crypto-rustcrypto` and `crypto-fips` are mutually exclusive. Do not use `--all-features`.

Container integration tests require Docker:

```bash
docker build -t async-snmp-test:latest tests/containers/snmpd/
cargo test --test testcontainers
```

### Documentation

Build and preview documentation:

```bash
cargo doc --features agent,crypto-rustcrypto,cli,mib,rt-multi-thread --open
```

## Pull Requests

- Keep changes focused on a single feature or fix
- Add tests for new functionality
- Update documentation as needed
- Ensure CI passes before requesting review
- Follow existing code style and patterns


## Reporting Issues

When reporting bugs, please include:

- Rust version (`rustc --version`)
- Operating system
- Minimal reproduction case
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (MIT OR Apache-2.0).
