# Architecture

SPECTRE is a single Rust application with separate analysis, command, event, and rendering layers. A shared event format is the integration boundary.

```text
CLI or terminal command
          │
          ▼
    command dispatcher ──────► scope and configuration
          │
          ▼
  binary / PCAP / TCP / HTTP analyzers
          │
          ▼
       EventHub ◄───────────── local host and process collector
          │
          ├── bounded history ──► JSON Lines export
          ├── subject links
          ├── exact indicator matches
          └── bounded broadcast ─► terminal workspace
```

## Event contract

`src/model.rs` defines `Event`, `Evidence`, `Severity`, and `SourceKind`. A recorded event includes an ID, UTC timestamp, module, kind, summary, optional subject, severity, source, and evidence. Every evidence entry carries its label, value, and origin. Current source variants are `live`, `file`, `recorded`, `prepared`, and `derived`.

The source field describes where an event came from. Offline binary and PCAP observations use `file`; local and scoped network observations use `live`. A completed prepared input is recorded with `prepared` provenance and remains separate from executed commands. Subject links and indicator matches use `derived`. The `recorded` variant is reserved for replay support, which is not implemented yet. A severity is a triage label, not a claim of exploitability.

`EventHub` in `src/engine.rs` stores a bounded `VecDeque` and sends new events through a bounded Tokio broadcast channel. A lagging receiver can miss notifications while history remains available up to its retention limit. When the correlation module is enabled, the current rule emits one subject link when two distinct modules publish events for the same subject. It lists source event IDs. It does not infer causation, identify a vulnerability, or merge evidence from different subjects. JSON Lines export writes the current in-memory history; there is no persistent case database yet.

The hub also evaluates configured exact indicators against selected observation fields through `src/detection.rs`. SHA-256 values are checked on binary identity/container events; domains on PCAP DNS questions, TLS SNI, HTTP Host, and web response hosts; IPs on PCAP flow addresses, TCP open addresses, and web response hosts that are literal IPs. Values are canonicalized before comparison. A match emits a `detection / indicator.match` event with `derived` source, the source event ID and timestamp, the matched field, and the configured indicator. Prepared and derived events are excluded from matching, so displayed scenarios and prior matches cannot generate new matches. This is an exact evidence link, not a malware verdict or threat-feed result.

## Analysis paths

| Module | Input and output | Important bound |
| --- | --- | --- |
| Host and process | `sysinfo` samples and process changes, published while the workspace runs | Five-second collection interval; at most 24 individual new-process events per interval |
| Binary | A local regular file parsed by `object`; identity, SHA-256, sections, imports, libraries, exports, symbols, strings; local process baseline and follow-up when enabled | 64 MiB input; `local-research`: 16 initial paths, 64 inspected paths, one analysis slot; `binary-monitor`: 128 initial paths, 512 inspected paths, two slots |
| PCAP | A local classic PCAP file; directional flows and selected application metadata | 512 MiB file, 200,000 packets, bounded flow and name tables |
| TCP | One named target resolved to IP addresses, selected TCP ports, connect results and passive banners | Up to 128 ports per command, 8 resolved addresses, 64 concurrent connections |
| HTTP | One GET to an explicit HTTP(S) URL, response headers and cookie attributes | Eight-second request timeout through command dispatcher; no redirects or proxy |
| Indicator matching | User-configured SHA-256, domain, and IP values checked against supported observations | At most 1,024 configured indicators and 64 matches emitted from one source event |

The PCAP decoder accepts Ethernet, raw IP, and Linux cooked v1/v2 captures. DNS questions, TLS SNI, and HTTP Host extraction operate on packet payloads. TCP stream reassembly, fragmented application records, PCAPNG, and live capture are outside the current parser. Binary inspection is static: it does not execute or disassemble the file. High section entropy is reported as an observation with its uncertainty, not a malware verdict.

When the `binary` and `process` modules are enabled, the collector includes its own executable when available and selects additional unique paths from the process snapshot, ordered by resident memory. It schedules at most one baseline executable per five-second tick. `local-research` starts with up to 16 paths, remembers at most 64 distinct paths, and runs one analysis at a time. `binary-monitor` starts with up to 128 paths, remembers at most 512, and runs up to two analyses concurrently. Other profiles with the binary module manually enabled use the conservative budget. New process executables can also be inspected within those limits. After the baseline queue drains, the collector checks one watched executable per tick for changes in file size or modification time. A changed file is reanalyzed when a slot is available; an unavailable file produces a separate observation. This is metadata drift detection on a bounded set of observed paths, not complete filesystem coverage or cryptographic integrity monitoring.

TCP scanning uses only configured ports and the exact target the user added to scope. A port convention is a hint; a protocol label is added only when a passive banner supports it. HTTP inspection records the response it receives and does not follow its `Location` header. A successful HTTPS request establishes only that the client accepted the peer under its TLS trust settings. The current analyzer does not report cipher suites or certificate-chain details.

The `investigate` command coordinates a TCP scan with HTTP follow-up on open ports 80, 443, 8080, and 8443, if those ports were selected. It caps follow-up at four observed endpoints and emits a derived completion event. Each HTTP request pins its connection to the address observed by the TCP scan while retaining the configured URL host for HTTP Host and TLS SNI. The response records that endpoint in evidence. This workflow is a bounded first correlation path, not a vulnerability scan.

## Runtime and interface

`src/main.rs` exposes terminal and headless commands. Headless `--json` emits complete events as JSON Lines. `src/command.rs` parses workspace commands without a shell and enforces exact-match target scope for active network work. `src/config.rs` normalizes scope hostnames to lowercase and IP addresses to canonical form, loads and validates TOML configuration, then writes changes through a temporary file. On a missing configuration, it recommends `binary-monitor` when detected RAM is at least 8 GiB and `local-research` otherwise. Built-in profiles select different local modules. A Tokio watch channel carries configuration changes to the autonomous collector; the command worker refreshes the hub's indicator set after configuration changes. The workspace starts local collection unless its profile or configuration disables it. External network analysis is initiated by an explicit command.

`src/tui.rs` uses Ratatui and Crossterm. It renders events, subjects, and evidence from the hub. The autonomous, interactive, and assisted modes change input handling. They do not create separate analyzer stacks. Assisted text is revealed from `prepared_workflow`. When the user completes a step, the command worker records a `prepared.input` event but does not execute the step text. The worker also receives real commands entered in interactive mode.

The interface responds to terminal resize and switches between three-column, two-column, and stacked layouts at different widths. Four bundled palettes are available. The current layout is a set of responsive presets; user-defined pane graphs are planned work.

## Extension boundary

The present module boundary is a Rust function that returns `Vec<Event>` or publishes events through `EventHub`. New analyzers should keep collection separate from rendering, bound memory and runtime, preserve the origin of evidence, and avoid stronger conclusions than the input supports. Third-party plugin loading and permission negotiation are not implemented. An extension API needs a versioned event schema, scoped capabilities, lifecycle management, and isolation before it can be treated as a supported interface.
