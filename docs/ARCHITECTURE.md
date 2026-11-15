# Architecture

SPECTRE is a single Rust application with separate analysis, command, event, and rendering layers. A shared event format is the integration boundary.

```text
CLI or terminal command
          │
          ▼
    command dispatcher ──────► scope and configuration
          │
          ▼
  binary / PCAP / process / traffic / TCP / HTTP / LAN analyzers
          │
          ▼
       EventHub ◄───────────── local host, process, and traffic collector
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

The hub also evaluates configured exact indicators against selected observation fields through `src/detection.rs`. SHA-256 values are checked on binary identity/container events; domains on PCAP DNS questions, TLS SNI, HTTP Host, and web response hosts; IPs on PCAP flow addresses, exact-target TCP open addresses, LAN host and open-port addresses, and web response hosts that are literal IPs. Values are canonicalized before comparison. A match emits a `detection / indicator.match` event with `derived` source, the source event ID and timestamp, the matched field, and the configured indicator. Prepared and derived events are excluded from matching, so displayed scenarios and prior matches cannot generate new matches. This is an exact evidence link, not a malware verdict or threat-feed result.

## Analysis paths

| Module | Input and output | Important bound |
| --- | --- | --- |
| Host and process | `sysinfo` samples and process changes, published while the workspace runs | Five-second collection interval; at most 24 individual new-process events per interval |
| Process investigation | An on-demand top-process snapshot sorted by resident memory or metadata for one current PID, including `self` | At most 32 top entries per request; visibility depends on platform permissions and whether the PID still exists; no process attach or memory read |
| Interface traffic | On-demand cumulative byte totals and periodic per-interface byte and packet deltas, with byte rates | Up to 16 addressed or nonzero nonloopback interfaces per snapshot; up to eight changing interfaces every ~15 seconds; no packet payloads, destinations, or process attribution |
| Binary | A local regular file parsed by `object`; identity, SHA-256, sections, imports, libraries, exports, symbols, strings; local process baseline and follow-up when enabled | 64 MiB input; `local-research`: 16 initial paths, 64 inspected paths, one analysis slot; `binary-monitor`: 128 initial paths, 512 inspected paths, two slots |
| PCAP | A local classic PCAP file; directional flows and selected application metadata | 512 MiB file, 200,000 packets, bounded flow and name tables |
| TCP | One named target resolved to IP addresses, selected TCP ports, connect results and passive banners | Up to 128 ports per command, 8 resolved addresses, 64 concurrent connections |
| LAN survey | A selected private IPv4 interface, its connected segment capped at /24, real TCP probe outcomes, and bounded HTTP follow-up on open web ports | One segment of up to 253 peer addresses per explicit run; eight TCP ports, 128 concurrent probes, 400 ms per connection attempt; at most 12 web follow-ups with a three-second timeout |
| HTTP | One GET to an exact-target HTTP(S) URL or an observed open LAN web endpoint; response headers and cookie attributes | Eight-second exact-target timeout or three-second LAN follow-up timeout; no redirects or proxy |
| Indicator matching | User-configured SHA-256, domain, and IP values checked against supported observations | At most 1,024 configured indicators and 64 matches emitted from one source event |

The PCAP decoder accepts Ethernet, raw IP, and Linux cooked v1/v2 captures. DNS questions, TLS SNI, and HTTP Host extraction operate on packet payloads. TCP stream reassembly, fragmented application records, PCAPNG, and live capture are outside the current parser. The live `traffic` module reads operating-system interface counters; its bytes and packets are totals or sample deltas, not captured network packets or attributed connections. Binary inspection is static: it does not execute or disassemble the file. High section entropy is reported as an observation with its uncertainty, not a malware verdict.

When the `binary` and `process` modules are enabled, the collector includes its own executable when available and selects additional unique paths from the process snapshot, ordered by resident memory. It schedules at most one baseline executable per five-second tick. `local-research` starts with up to 16 paths, remembers at most 64 distinct paths, and runs one analysis at a time. `binary-monitor` starts with up to 128 paths, remembers at most 512, and runs up to two analyses concurrently. Other profiles with the binary module manually enabled use the conservative budget. New process executables can also be inspected within those limits. After the baseline queue drains, the collector checks one watched executable per tick for changes in file size or modification time. A changed file is reanalyzed when a slot is available; an unavailable file produces a separate observation. This is metadata drift detection on a bounded set of observed paths, not complete filesystem coverage or cryptographic integrity monitoring.

Exact-target TCP scanning uses only configured ports and the target the user added to scope. A port convention is a hint; a protocol label is added only when a passive banner supports it. The separate LAN survey chooses the private IPv4 interface selected by the route where possible and surveys its connected segment, capped at /24. A narrower connected segment stays narrow. Detecting that segment is passive; its active probes run only after a `lan survey` command or an explicit Assisted action. The TCP probes and web follow-ups bind to the selected local IPv4 address. An open or refused TCP response supports a host observation; silence is inconclusive. The survey follows up on at most 12 observed open web endpoints with an HTTP(S) GET pinned to the observed address. It records response events or explicit failures with the originating TCP event ID and endpoint; that TCP event can later age out of bounded in-memory history. The prepared survey command carries the detected CIDR, and the worker checks it against the current interface before starting the probes. HTTP inspection records the response it receives and does not follow its `Location` header. A successful HTTPS request establishes only that the client accepted the peer under its TLS trust settings. The current analyzer does not report cipher suites or certificate-chain details.

The `investigate` command coordinates a TCP scan with HTTP follow-up on open ports 80, 443, 8080, and 8443, if those ports were selected. It caps follow-up at four observed endpoints and emits a derived completion event. Each HTTP request pins its connection to the address observed by the TCP scan while retaining the configured URL host for HTTP Host and TLS SNI. The response records that endpoint in evidence. This workflow is a bounded first correlation path, not a vulnerability scan.

## Runtime and interface

`src/main.rs` exposes terminal and headless commands. Headless `--json` emits complete events as JSON Lines. `src/command.rs` parses workspace commands without a shell, enforces exact-match target scope for named targets, and checks the current local segment before a LAN survey. On-demand `process top`, `process inspect`, and `traffic snapshot` read current OS data. `src/config.rs` normalizes scope hostnames to lowercase and IP addresses to canonical form, loads and validates TOML configuration, then writes changes through a temporary file. On a missing configuration, it recommends `binary-monitor` when detected RAM is at least 8 GiB and `local-research` otherwise. Built-in profiles select different local modules. `lan_assessment_enabled` controls availability of the local-network session; it does not start background network probing. A Tokio watch channel carries configuration changes to the autonomous collector; the command worker refreshes the hub's indicator set after configuration changes. The workspace starts configured local host, process, and traffic collection unless its profile or configuration disables it. Active network analysis is initiated by a user action.

`src/tui.rs` uses Ratatui and Crossterm. It renders events, subjects, and evidence from the hub. The autonomous, interactive, and assisted modes change input handling. They do not create separate analyzer stacks. `src/assisted.rs` places **System and network** first. This combined scenario runs `doctor`, `module list`, `traffic snapshot`, `process top`, `process inspect self`, binary inspection of a real executable, and `indicator list`; when LAN assessment is on, it adds `lan status`, `lan survey <detected CIDR>`, and `lan report`; it ends with `triage`. It has 11 stages with LAN on or eight with LAN off. The F5 `n` toggle changes only that LAN portion and the dedicated LAN scenario's availability. If no suitable interface is detected, the context and survey stages report errors and the other stages continue.

Other built-in scenarios are seven-stage local research, three-stage process investigation (`process top`, `process inspect self`, `triage`), the dedicated LAN scenario when enabled, and one exact-target scenario per configured target. An optional custom sequence comes from `prepared_workflow`. `F6` runs every stage of the selected built-in scenario with one action. For stage-by-stage use, prepared typing and Enter execute passive or local steps; an active network step requires `Ctrl+R` after full reveal. The UI advances manual stages only after worker acknowledgement and keeps failed stages available for retry. Execution markers cite their result event IDs; custom prepared text is never executed.

The interface responds to terminal resize and switches between three-column, two-column, and stacked layouts at different widths. Four bundled palettes are available. The current layout is a set of responsive presets; user-defined pane graphs are planned work.

## Extension boundary

The present module boundary is a Rust function that returns `Vec<Event>` or publishes events through `EventHub`. New analyzers should keep collection separate from rendering, bound memory and runtime, preserve the origin of evidence, and avoid stronger conclusions than the input supports. Third-party plugin loading and permission negotiation are not implemented. An extension API needs a versioned event schema, scoped capabilities, lifecycle management, and isolation before it can be treated as a supported interface.
