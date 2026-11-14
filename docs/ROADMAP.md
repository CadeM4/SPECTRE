# Roadmap

The current implementation covers local observation, a bounded executable baseline and metadata drift checks, static binary analysis, classic PCAP inspection, scoped TCP and HTTP assessment, exact user-configured indicator matching, an event hub, JSON Lines export, and a responsive terminal workspace. The items below are proposed work, not capabilities advertised as complete.

## Next engineering work

1. **Evidence and sessions.** Introduce a durable investigation store, event schema versioning, bookmarks, annotations, and reproducible exports. Add migration tests before changing the schema.
2. **Collector control.** Move local collection to independently supervised modules with cancellation, deadlines, and backoff. Expose the current profile-based binary budgets for user configuration, add durable executable baselines and hash-aware integrity comparisons, and show a clear task list in the interface.
3. **Network depth.** Add protocol-aware service inspection, TLS certificate and negotiation details, richer HTTP assessment, and explicit DNS resolution history. Keep active work tied to configured scope.
4. **Packet depth.** Add PCAPNG, IPv4 fragmentation and TCP stream reassembly, richer DNS and TLS parsing, and live capture through a capability-gated backend.
5. **Binary workspace.** Add disassembly, symbol and string navigation, binary comparison, signature verification, and supported debugger or instrumentor integrations.
6. **Interface and configuration.** Add configurable pane graphs, saved layouts, contextual command completion, more complete in-app configuration, and editable custom profiles.

## Later exploration

- Versioned plugin API with explicit capabilities, process isolation, and compatibility checks.
- Richer detection rules and external threat intelligence enrichment tied to source evidence.
- Container and cloud configuration assessment through opt-in credentials.
- Recorded investigations and assisted workflows with import, export, and replay provenance.
- Cross-platform installers, signed release artifacts, and distribution through appropriate package managers.

Each addition should preserve bounded resource use and distinguish observations from hypotheses or confirmed findings. Platform-specific capabilities require platform-specific tests.

## Licensing and release

No project license has been granted yet. For the intended open-source Rust distribution, the recommended option is **MIT OR Apache-2.0**, which lets recipients choose either permissive license. Apache-2.0 includes an express patent grant; the dual-license form is documented by [Cargo](https://doc.rust-lang.org/cargo/reference/manifest.html#the-license-and-license-file-fields) and is common in the Rust ecosystem. The [OSI Apache-2.0 text](https://opensource.org/license/apache-2.0) sets out its terms. This is a recommendation for Cade Masterson to decide before public release, not an effective license statement.

Before publication, select the license, add its full text and a matching Cargo manifest field, review dependency notices, verify builds on macOS/Linux/Windows, capture accurate interface screenshots, and publish a tagged release with checksums. Binary releases and package manager entries should follow verified platform builds.
