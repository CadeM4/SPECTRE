# Usage

## Commands

Run `spectre --help` for the current top-level syntax. The same analysis operations can be entered at the workspace prompt using the short forms below.

| Terminal command | Workspace prompt | Purpose |
| --- | --- | --- |
| `spectre` or `spectre launch` |  | Open the terminal workspace. |
| `spectre doctor` | `doctor` | Report OS, architecture, terminal availability, built-in modules, and optional tools found on `PATH`. |
| `spectre doctor --json` |  | Print the capability report as JSON. |
| `spectre version` or `spectre --version` |  | Show the installed version; `spectre version` also prints creator attribution. |
| `spectre analyze binary PATH` | `binary PATH` | Inspect a local executable or object file. |
| `spectre analyze pcap PATH` | `pcap PATH` | Inspect a classic PCAP file. |
| `spectre scope add HOST` | `scope add HOST` | Add an exact host or IP string to the configured target list. |
| `spectre scope remove HOST` | `scope remove HOST` | Remove that entry. |
| `spectre scope list` | `scope list` | Show configured targets. |
| `spectre indicators` | `indicator list` | List configured exact indicators. |
| `spectre indicators add KIND VALUE [LABEL]` | `indicator add KIND VALUE [LABEL]` | Add or replace an indicator. |
| `spectre indicators remove KIND VALUE` | `indicator remove KIND VALUE` | Remove an indicator. |
| `spectre profiles` or `spectre profiles NAME` | `profile list` or `profile NAME` | List or select a bundled local collection profile. |
| `spectre themes` or `spectre themes NAME` | `theme list` or `theme NAME` | List or select a terminal theme. |
| `spectre modules` or `spectre modules enable|disable NAME` | `module list` or `module enable|disable NAME` | Inspect or change autonomous modules. |
|  | `autonomous on|off` | Change local collection at runtime and save the setting. |
|  | `workflow list`, `workflow add TEXT`, `workflow remove INDEX`, `workflow clear` | Manage the ordered assisted input sequence. Indices start at 1. |
|  | `retention`, `retention set COUNT` | Show or save the event history limit. The hub uses the new limit on the next launch. |
| `spectre scan HOST --ports 22,80,443` | `scan HOST 22,80,443` | Run bounded TCP connect checks. |
| `spectre investigate HOST --ports 22,80,443` | `investigate HOST 22,80,443` | Scan selected ports and inspect HTTP on observed open web ports. |
| `spectre http URL` | `http URL` | Inspect one HTTP(S) response. |
| `spectre configure` |  | Print the active configuration and its path, creating defaults if needed. |
| `spectre configure --init` |  | Write the current/default configuration at the selected path. |
|  | `export PATH` | Write the current in-memory events as JSON Lines. |
|  | `help` | Show workspace command forms. |

Use `--config PATH` with any top-level command to select a different TOML file. Quote paths with spaces at the workspace prompt. The prompt parses command arguments directly and does not invoke a shell.

Headless analysis commands accept `--json` and emit one complete event per JSON line, including derived links. The default text view abbreviates long evidence values. `doctor --json` emits one formatted JSON capability report. Event timestamps in headless text output end in `Z` and are UTC.

The default scan ports are `21,22,25,53,80,110,143,443,445,3389,5432,6379,8080,8443`. A command accepts at most 128 ports; a single inclusive range may contain at most 128. Examples:

```sh
spectre scope add example.org
spectre scan example.org --ports 22,80,443,8000-8010
spectre investigate example.org --ports 22,80,443
spectre http https://example.org/
spectre analyze binary "/path with spaces/program"
```

Scope matching uses a single normalized hostname or IP address. Hostnames are case insensitive, and IPv6 addresses are stored in canonical form; optional brackets are accepted when adding an IPv6 scope entry. Adding `example.org` does not authorize `www.example.org`, a resolved sibling IP, or an entire subnet. HTTP commands compare the URL host to the configured entry. Adding a target only changes configuration; it does not initiate collection. No background network scan is enabled by the default configuration.

`investigate` uses ports `22,80,443,8080,8443` by default. It follows up only when one of the conventional web ports in its selection is observed open, with at most four endpoint checks. Each request pins the connection to the IP address recorded by the TCP scan while keeping the configured hostname for HTTP Host and TLS SNI. It emits a derived completion event and retains the individual TCP and HTTP observations. A web request can fail even when a TCP connection succeeded; the follow-up error records the attempted endpoint.

## Workspace keys

| Key | Action |
| --- | --- |
| `F1` | Open or close help. |
| `F2` | Cycle autonomous, interactive, and assisted input modes. |
| `F3` | Cycle overview, timeline, and evidence views. |
| `F4` | Cycle the four themes. |
| `F5` | Open workspace settings. |
| `Ctrl+J` / `Ctrl+K` | Select newer or older observation. |
| `PageDown` / `PageUp` | Move selection by ten observations. |
| `/` in autonomous mode | Open interactive command input. |
| `Up` / `Down` in interactive mode | Recall command history. |
| `Enter` in interactive mode | Submit the typed command. |
| `Esc` in interactive mode | Clear input and return to autonomous input. |
| `Ctrl+C` | Exit. |

The settings panel currently changes profile (`p`), theme (`t`), view arrangement (`l`), refresh interval (`r`), and local autonomous collection (`a`). Profile, theme, refresh, and autonomous settings are saved. The arrangement applies to the current workspace session. The terminal must be at least 48 columns by 10 rows; the layout becomes denser as width increases.

### Assisted input

At the workspace prompt, add steps and inspect the sequence, then press `F2` until the assisted mode is selected:

```text
workflow add "binary /path/to/program"
workflow add "pcap /path/to/capture.pcap"
workflow list
```

Use `workflow remove 2` to remove one step or `workflow clear` to empty the sequence. The entries are saved in `prepared_workflow` in the configuration, with at most 256 steps and 4,096 bytes per step. These commands do not execute the prepared text. To change the event limit from the prompt, use `retention set 5000`; the workspace display adopts it immediately, and the event hub adopts it on the next launch.

Each ordinary character key reveals the next character of the current entry, regardless of the key's character. Backspace retracts one revealed character. Enter advances only after the entry is complete. Escape resets the current entry. Control keys do not advance it. When Enter completes a fully revealed step, the workspace records a `prepared.input` event with `prepared` provenance and the configured text. Typing `present` at the interactive prompt cannot create that event. Prepared text is never executed. The event is included in a JSON Lines export if it remains in memory. To run an operation, switch to interactive mode and enter a real command. Local background collection can continue while assisted input is shown.

This is a minimal prepared sequence implementation. Multi-field scenario editing, recorded playback, command-aware fields, and controlled execution transitions remain planned work.

## Configuration

Run `spectre configure` to locate the platform-specific configuration file. The current keys are:

| Key | Default | Meaning |
| --- | --- | --- |
| `profile` | Recommended on first run | One of the bundled local collection presets or `custom`. |
| `theme` | `intelligence` | `intelligence`, `arctic`, `amber`, or `monochrome`. |
| `refresh_ms` | `500` | Terminal refresh interval; validated from 100 to 10,000 ms. |
| `retention_events` | `2000` | Maximum in-memory event history; validated from 100 to 100,000. |
| `autonomous` | `true` | Start local collection when launching the workspace. |
| `allowed_targets` | `[]` | Exact-match hosts or IP strings for active commands. |
| `enabled_modules` | Selected by first-run profile | Local modules to run. `binary` enables bounded baseline and follow-up inspection of observed process executables and requires `process`; `correlation` enables subject links. |
| `prepared_workflow` | `[]` | Assisted input entries. |
| `indicators` | `[]` | Exact SHA-256, domain, and IP values evaluated against supported observations. |

`doctor` lists optional tools such as TShark, nmap, and Ghidra when they are on `PATH`. These are discovery results, not active integrations. An unavailable optional tool does not prevent the built-in analyzers from running.

Bundled profiles are `local-research` (host, process, correlation, and a small executable baseline), `binary-monitor` (the same modules with a larger binary budget), `focused` (process and correlation), and `offline` (no autonomous collection). `custom` preserves the current module selection. On first run, SPECTRE recommends `binary-monitor` when it detects at least 8 GiB of RAM and `local-research` otherwise. If memory inspection is unavailable, it uses `local-research`. `spectre doctor` reports the recommendation. Selecting a profile saves its settings and updates the running collector in the workspace.

With `local-research`, the collector selects up to 16 executables from the initial process inventory, including SPECTRE's own executable when available. It remembers at most 64 distinct paths, queues at most 64 pending paths, and runs one binary analysis at a time. `binary-monitor` raises those limits to 128 initial executables, 512 distinct paths, 256 pending paths, and two analysis slots. Both profiles analyze at most one baseline path per five-second interval; newly observed process executables may also be inspected. Once the baseline queue is empty, one watched path is checked per interval for a changed size or modification time. A change can trigger reanalysis; the check does not prove the file content changed and is not a full filesystem integrity scan.

### Exact indicators

Use `spectre indicators add` to store a local value and optional label:

```sh
spectre indicators add domain example.org "research set"
spectre indicators add ip 192.0.2.10 "case-42"
spectre indicators
```

Equivalent TOML entries use `[[indicators]]` tables:

```toml
[[indicators]]
kind = "domain"
value = "example.org"
label = "research set"
```

Kinds are `sha256`, `domain`, and `ip`. SHA-256 values must be 64 hexadecimal characters. Domain values are ASCII DNS names without a scheme or port; comparison ignores case and one trailing dot. IP values accept IPv4 or IPv6 and are compared in canonical form. Labels contain 1 to 256 printable characters; the CLI uses `configured indicator` when no label is supplied. Up to 1,024 indicators can be stored. Adding the same kind and value again replaces its label. The `remove` command removes by kind and value.

The matcher checks specific fields: binary SHA-256 identity/container hashes; PCAP DNS questions, TLS SNI, HTTP Host, and flow source/destination IPs; HTTP response hosts; and resolved IP addresses on open TCP observations. A domain indicator matches the complete hostname, not a subdomain or substring. A match creates a `derived` event with the source event ID, timestamp, matched field, indicator kind/value/label, and medium triage severity. It records an exact relationship between a configured value and an observation. It is not a malware verdict, reputation check, or vulnerability finding. Prepared text and derived events are not matched. Configuring an indicator does not perform network activity or change authorized target scope.

## Evidence and limits

Events include a `source` field and evidence origins. File analysis outputs reference the file path; network events reference the request or connection that produced them. Correlation links events by matching subject strings and lists their event IDs. Indicator matches link a configured value to a specific observed field. These derived events are navigation and triage aids, not independent proof of a security issue.

The current export contains only events retained in memory for the running workspace. `export PATH` creates a new file and refuses to replace an existing path. Exported JSON Lines can include local paths, process names, target addresses, HTTP headers, packet metadata, configured indicator values, and prepared input text. Review the file before sharing it. Binary analysis is limited to 64 MiB files. Classic PCAP analysis is limited to 512 MiB and 200,000 packets; PCAPNG is not yet accepted. HTTP inspection does not follow redirects, and its header observations describe one response rather than an entire site.
