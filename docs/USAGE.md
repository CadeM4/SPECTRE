# Usage

## Commands

Run `spectre --help` for the current top-level syntax. The same analysis operations can be entered at the workspace prompt using the short forms below.

| Terminal command | Workspace prompt | Purpose |
| --- | --- | --- |
| `spectre` or `spectre launch` |  | Open the terminal workspace. |
| `spectre doctor` | `doctor` | Report OS, architecture, terminal availability, built-in modules, detected private LAN segment, and optional tools found on `PATH`. No probes are sent. |
| `spectre doctor --json` |  | Print the capability report as JSON. |
|  | `triage` | Summarize retained observation counts by module and severity, recent subjects, indicator match and correlation link counts, and latest observation IDs. |
| `spectre version` or `spectre --version` |  | Show the installed version; `spectre version` also prints creator attribution. |
| `spectre analyze binary PATH` | `binary PATH` | Inspect a local executable or object file. |
| `spectre analyze pcap PATH` | `pcap PATH` | Inspect a classic PCAP file. |
| `spectre process top [--limit N]` | `process top [N]` | List the current top processes by resident memory, with their PIDs. Defaults to 10; accepts 1 to 32. |
| `spectre process inspect PID` | `process inspect PID` | Read metadata for one current process. Use `self` in place of a PID for SPECTRE's own process. |
| `spectre traffic snapshot` | `traffic snapshot` | Read current cumulative byte totals for nonloopback interfaces. |
| `spectre scope add HOST` | `scope add HOST` | Add an exact host or IP string to the configured target list. |
| `spectre scope remove HOST` | `scope remove HOST` | Remove that entry. |
| `spectre scope list` | `scope list` | Show configured targets. |
| `spectre lan status` | `lan status` | Show the selected private IPv4 interface and exact local survey range without sending probes. |
| `spectre lan on` or `spectre lan off` | `lan on` or `lan off` | Enable or disable the local-network assisted session. This setting does not start a scan. |
| `spectre lan survey` | `lan survey [CIDR]` | Probe the selected local segment, follow up on observed open web ports, and report actual responses. An optional CIDR must match the currently detected segment. |
|  | `lan report` | Summarize LAN observations retained in the running workspace. |
| `spectre indicators` | `indicator list` | List configured exact indicators. |
| `spectre indicators add KIND VALUE [LABEL]` | `indicator add KIND VALUE [LABEL]` | Add or replace an indicator. |
| `spectre indicators remove KIND VALUE` | `indicator remove KIND VALUE` | Remove an indicator. |
| `spectre profiles` or `spectre profiles NAME` | `profile list` or `profile NAME` | List or select a bundled local collection profile. |
| `spectre themes` or `spectre themes NAME` | `theme list` or `theme NAME` | List or select a terminal theme. |
| `spectre modules` or `spectre modules enable|disable NAME` | `module list` or `module enable|disable NAME` | Inspect or change autonomous modules. |
|  | `autonomous on|off` | Change local collection at runtime and save the setting. |
|  | `workflow list`, `workflow add TEXT`, `workflow remove INDEX`, `workflow clear` | Manage optional custom assisted presentation steps. Indices start at 1. |
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

Scope matching for named targets uses a single normalized hostname or IP address. Hostnames are case insensitive, and IPv6 addresses are stored in canonical form; optional brackets are accepted when adding an IPv6 scope entry. Adding `example.org` does not authorize `www.example.org`, a resolved sibling IP, or an entire subnet. HTTP commands compare the URL host to the configured entry. Adding a target only changes configuration; it does not initiate collection. The local-network survey is a separate action that detects a private IPv4 interface and selects its connected segment, capped at the /24 containing its address. A narrower connected subnet stays narrow. No background network scan is enabled by the default configuration.

For a real survey of the current local segment, check the range first:

```sh
spectre lan status
spectre lan survey
```

`lan status` is passive. `lan survey` makes TCP connection attempts to hosts in the displayed segment on ports 22, 53, 80, 443, 445, 3389, 8080, and 8443. It emits observed host, open-port, and completion events. It probes at most 253 peer addresses, with 128 concurrent connection attempts and a 400 ms timeout per probe. The probes bind to the selected local IPv4 address. Up to 12 observed open web endpoints on ports 80, 443, 8080, or 8443 receive one HTTP(S) GET each, pinned to the observed IP address with a three-second timeout. Response and follow-up error events record the originating TCP event ID and endpoint; redirects are not followed. SPECTRE infers reachability from open or refused TCP responses; a host that does not answer those probes may still exist. The workspace form accepts `lan survey CIDR` to pin the displayed segment; it refuses to run if the detected network has changed. `spectre lan off` removes the LAN stages from the default Assisted session, hides the dedicated LAN scenario, and disables the survey command until `spectre lan on` is run. Exact-target `scan`, `investigate`, and `http` commands still use their own configured scope.

For live process and traffic data from this computer:

```sh
spectre process top
spectre process inspect self
spectre traffic snapshot
```

Replace `self` with a PID from `process top` to inspect that process. Process inspection reads available OS metadata, including memory, status, start time, parent PID, and executable path when visible; it does not attach to the process or read its memory. A process may exit between listing and inspection. `traffic snapshot` reports cumulative byte totals for up to 16 nonloopback interfaces that have an address or nonzero counters, ordered by total traffic. With the `traffic` autonomous module enabled, SPECTRE samples about every 15 seconds and reports received/transmitted byte and packet changes for up to eight interfaces whose counters changed, plus byte rates for the sample interval. These values describe aggregate interface traffic; they are not a packet capture, a list of connections, or a measurement attributed to a process.

`investigate` uses ports `22,80,443,8080,8443` by default. It follows up only when one of the conventional web ports in its selection is observed open, with at most four endpoint checks. Each request pins the connection to the IP address recorded by the TCP scan while keeping the configured hostname for HTTP Host and TLS SNI. It emits a derived completion event and retains the individual TCP and HTTP observations. A web request can fail even when a TCP connection succeeded; the follow-up error records the attempted endpoint.

## Workspace keys

| Key | Action |
| --- | --- |
| `F1` | Open or close help. |
| `F2` | Cycle autonomous, interactive, and assisted input modes. |
| `F3` | Cycle overview, timeline, and evidence views. |
| `F4` | Cycle the four themes. |
| `F5` | Open workspace settings. |
| `F6` in assisted mode | Run every stage of the selected built-in session with one key. The first/default session includes a real LAN survey when LAN assessment is on. |
| `Tab` / `Shift+Tab` in assisted mode | Select the next or previous built-in or custom scenario. |
| `Left` in assisted mode | Return to the previous stage and reset its prepared input. |
| `Enter` in assisted mode | After a full reveal, run a local built-in step; record and advance an active network or custom step without running it. |
| `Ctrl+R` in assisted mode | Explicitly run a fully revealed active step in a network scenario. |
| `Ctrl+J` / `Ctrl+K` | Select newer or older observation. |
| `PageDown` / `PageUp` | Move selection by ten observations. |
| `/` in autonomous mode | Open interactive command input. |
| `Up` / `Down` in interactive mode | Recall command history. |
| `Enter` in interactive mode | Submit the typed command. |
| `Esc` in interactive mode | Clear input and return to autonomous input. |
| `Ctrl+C` | Exit. |

The settings panel currently changes profile (`p`), theme (`t`), view arrangement (`l`), refresh interval (`r`), local autonomous collection (`a`), and LAN assessment (`n`). Profile, theme, refresh, autonomous, and LAN settings are saved. Turning LAN assessment off omits the LAN stages from the default Assisted session and hides the dedicated LAN scenario; the local stages still run. The arrangement applies to the current workspace session. The terminal must be at least 48 columns by 10 rows; the layout becomes denser as width increases.

### Assisted scenarios

No user-authored plan is needed. Press `F2` until **ASSISTED** appears. It opens on **System and network**, the default combined session. Press `F6` to run the complete sequence. With LAN assessment on, its 11 stages run `doctor`, `module list`, `traffic snapshot`, `process top`, `process inspect self`, `binary` on a real executable, `indicator list`, `lan status`, `lan survey` on the detected segment, `lan report`, and `triage`. The survey makes real TCP and selected HTTP(S) requests; the other stages read local data and retained evidence. With LAN assessment off, the three LAN stages are omitted, leaving eight local stages. No network survey starts merely by opening Assisted mode. If no suitable interface is detected, the context and survey stages report the problem while the remaining stages continue.

The focused **Local research** scenario has seven stages: Environment (`doctor`), Collection (`module list`), Interface traffic (`traffic snapshot`), Initial triage (`triage`), Binary inspection, Indicators (`indicator list`), and Final review (`triage`). Binary inspection prefers SPECTRE's executable when it fits the 64 MiB analyzer limit and otherwise uses a small real platform executable. Background local collection continues during an Assisted run. Each stage uses the same commands and evidence as interactive mode.

The separate process investigation scenario has three stages: `process top`, `process inspect self`, and `triage`. It reads current processes and inspects the running SPECTRE process as a concrete starting point. Select it with `Tab` and press `F6` to run the sequence. To inspect another PID, use `spectre process inspect PID` or the interactive prompt.

Each ordinary character key reveals the next character of the prepared input, regardless of the key pressed. Backspace retracts one character; Escape resets the current step; Left revisits the previous stage. After a local built-in command is fully revealed, Enter runs it and advances when the result arrives. If the step fails, it stays in place and Enter retries it. The resulting observations appear in the normal event stream. Enter does nothing until the current input is fully revealed.

Use `Tab` and `Shift+Tab` to switch scenarios. When LAN assessment is enabled, a local-network scenario is available. It detects the private IPv4 interface and shows the selected range when one is found. Its four stages are Network context (`lan status`), Host and service survey (`lan survey CIDR`), Survey review (`lan report`), and Final triage (`triage`). If no suitable interface is available, the context step reports that and the survey cannot run. A separate scoped network scenario appears for each exact target added to `allowed_targets`, for example with `scope add 192.168.1.1` in interactive mode. `F6` runs the selected exact-target sequence too. Select the scenario and check the displayed target or range before pressing `F6`; that key starts all active stages in the selected built-in session. No network survey starts merely by launching SPECTRE or switching to Assisted mode.

For manual stage-by-stage use, local review steps run on Enter after a full reveal. Active LAN survey, scan, investigation, and HTTP steps must be fully revealed and then run with `Ctrl+R`. Enter alone records and advances an active step without making the request. The exact-target scenario still enforces its configured target. Use `F5`, then `n`, or `lan on|off` at the interactive prompt to toggle the local-network session; the toggle does not alter exact-target scope.

Custom sequences remain available. In interactive mode, enter the following, then return to assisted mode and select the custom scenario with `Tab`:

```text
workflow add "binary /path/to/program"
workflow add "pcap /path/to/capture.pcap"
workflow list
```

For a custom step, Enter after the full reveal records a `prepared.input` event with `prepared` provenance and advances. Custom text is **never executed**. Use `workflow remove 2` or `workflow clear` to edit the sequence. Entries are saved in `prepared_workflow` in the configuration, with at most 256 steps and 4,096 bytes per step. Recorded prepared input is included in a JSON Lines export if it remains in memory. To run a custom command, switch to interactive mode and enter it there.

Assisted mode is a deterministic prepared presentation, not an AI assistant or a shell. To change the event limit from the interactive prompt, use `retention set 5000`; the workspace display adopts it immediately, and the event hub adopts it on the next launch.

## Configuration

Run `spectre configure` to locate the platform-specific configuration file. The current keys are:

| Key | Default | Meaning |
| --- | --- | --- |
| `profile` | Recommended on first run | One of the bundled local collection presets or `custom`. |
| `theme` | `intelligence` | `intelligence`, `arctic`, `amber`, or `monochrome`. |
| `refresh_ms` | `500` | Terminal refresh interval; validated from 100 to 10,000 ms. |
| `retention_events` | `2000` | Maximum in-memory event history; validated from 100 to 100,000. |
| `autonomous` | `true` | Start local collection when launching the workspace. |
| `lan_assessment_enabled` | `true` | Include the LAN survey in the default combined Assisted session and make the dedicated LAN scenario available. It sends no traffic until a survey is started. |
| `allowed_targets` | `[]` | Exact-match hosts or IP strings for active commands. |
| `enabled_modules` | Selected by first-run profile | Local modules to run. `traffic` samples interface counters; `binary` enables bounded baseline and follow-up inspection of observed process executables and requires `process`; `correlation` enables subject links. |
| `prepared_workflow` | `[]` | Optional custom assisted presentation entries. Built-in scenarios are available when this is empty. |
| `indicators` | `[]` | Exact SHA-256, domain, and IP values evaluated against supported observations. |

`doctor` checks process inspection, passive interface counters, and whether a suitable private LAN segment can be detected without sending probes. It also lists optional tools such as TShark, nmap, and Ghidra when they are on `PATH`. These tool results are discovery only, not active integrations. An unavailable optional tool does not prevent the built-in analyzers from running.

Bundled profiles are `local-research` (host, process, traffic, correlation, and a small executable baseline), `binary-monitor` (the same modules with a larger binary budget), `focused` (process and correlation), and `offline` (no autonomous collection). `custom` preserves the current module selection. On first run, SPECTRE recommends `binary-monitor` when it detects at least 8 GiB of RAM and `local-research` otherwise. If memory inspection is unavailable, it uses `local-research`. `spectre doctor` reports the recommendation. Selecting a profile saves its settings and updates the running collector in the workspace.

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

The matcher checks specific fields: binary SHA-256 identity/container hashes; PCAP DNS questions, TLS SNI, HTTP Host, and flow source/destination IPs; HTTP response hosts; resolved IP addresses on exact-target open TCP observations; and addresses in LAN host and open-port observations. A domain indicator matches the complete hostname, not a subdomain or substring. A match creates a `derived` event with the source event ID, timestamp, matched field, indicator kind/value/label, and medium triage severity. It records an exact relationship between a configured value and an observation. It is not a malware verdict, reputation check, or vulnerability finding. Prepared text and derived events are not matched. Configuring an indicator does not perform network activity or change authorized target scope.

## Evidence and limits

Events include a `source` field and evidence origins. File analysis outputs reference the file path; network events reference the request or connection that produced them. Correlation links events by matching subject strings and lists their event IDs. Indicator matches link a configured value to a specific observed field. These derived events are navigation and triage aids, not independent proof of a security issue.

The current export contains only events retained in memory for the running workspace. `export PATH` creates a new file and refuses to replace an existing path. Exported JSON Lines can include local paths, process names, target addresses, HTTP headers, packet metadata, configured indicator values, and prepared input text. Review the file before sharing it. Binary analysis is limited to 64 MiB files. Classic PCAP analysis is limited to 512 MiB and 200,000 packets; PCAPNG is not yet accepted. HTTP inspection does not follow redirects, and its header observations describe one response rather than an entire site. The LAN survey covers one selected private IPv4 segment of at most /24 size, not other local interfaces, VLANs, IPv6 networks, or networks beyond that segment. Its TCP observations are evidence of responses to the selected probes, not a complete device inventory.
