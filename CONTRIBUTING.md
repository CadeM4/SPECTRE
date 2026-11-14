# Contributing

SPECTRE is created and led by Cade Masterson. The codebase is in active development and a project license has not yet been selected. Discuss substantial external contributions with the project lead before submitting them. Existing third-party licenses and accurate contributor credit must be preserved.

## Development checks

Use the current stable Rust toolchain. Before proposing a change, run:

```sh
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Keep analyzers separate from terminal rendering. Events should include precise origins, bounded evidence, and a source type that matches the observation. A port number, binary entropy value, or missing HTTP header is not by itself proof of a vulnerability. Tests should exercise parsing boundaries, actual local behavior, and error conditions relevant to the change.

For network work, require an explicit target and respect configured scope. For offline work, avoid executing inspected files. When adding platform-specific code, document the platform and permission assumptions and add representative tests where the platform is available.

Small, focused changes are easier to review. Describe what changed, how it was verified, and any known limits. Do not commit captures, binaries, credentials, or exported investigations containing sensitive data unless they are intentionally synthetic and suitable for publication.
