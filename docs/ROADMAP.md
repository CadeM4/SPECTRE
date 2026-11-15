# Roadmap

The current implementation covers local observation, a bounded executable baseline and metadata drift checks, static binary analysis and limited disassembly, classic PCAP and short live capture, process resource and call-stack sampling, optional Frida function tracing, scoped TCP and HTTP assessment, exact user-configured indicator matching, four external intelligence sources, an event hub, JSON Lines export, and an evidence-driven terminal workspace. The items below extend those entry points.

## Next engineering work

1. **Evidence and sessions.** Introduce a durable investigation store, event schema versioning, bookmarks, annotations, and reproducible exports. Add migration tests before changing the schema.
2. **Collector control.** Move local collection to independently supervised modules with cancellation, deadlines, and backoff. Expose the current profile-based binary budgets for user configuration, add durable executable baselines and hash-aware integrity comparisons, and show a clear task list in the interface.
3. **Network depth.** Add protocol-aware service inspection, TLS certificate and negotiation details, richer HTTP assessment, and explicit DNS resolution history. Keep active work tied to configured scope.
4. **Packet depth.** Add PCAPNG, IPv4 fragmentation and TCP stream reassembly, richer DNS and TLS parsing, and deeper live-capture views with better interface and permission diagnostics.
5. **Binary and runtime workspace.** Add symbol-aware instruction navigation, cross-references, call graphs, binary comparison, signature verification, and broader runtime tracing and debugging views.
6. **Interface and configuration.** Add configurable pane graphs, saved layouts, contextual command completion, more complete in-app configuration, and editable custom profiles.

## Later exploration

- Versioned plugin API with explicit capabilities, process isolation, and compatibility checks.
- Richer detection rules, more intelligence providers, bulk investigation queues that honor provider quotas, and durable source-linked enrichment history.
- Container and cloud configuration assessment through opt-in credentials.
- Recorded investigations and assisted workflows with import, export, and replay provenance.
- Cross-platform installers, signed release artifacts, and distribution through appropriate package managers.

Each addition should preserve bounded resource use and distinguish observations from hypotheses or confirmed findings. Platform-specific capabilities require platform-specific tests.

## Licensing and release

SPECTRE is licensed under **MIT OR Apache-2.0**. Recipients may choose either [MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE), and Cargo declares the same expression. The project attribution belongs to Cade Masterson; dependency licenses and contributor credit remain intact.

Before the first tagged release, review dependency notices, verify source installs on macOS/Linux/Windows, prepare release notes, and publish platform artifacts with checksums. Binary releases and package manager entries should follow verified platform builds.
