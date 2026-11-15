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
| `spectre disassemble PATH [--instructions N]` | `disasm PATH [N]` | Decode a bounded number of instructions from a local executable section. |
| `spectre capture live [--interface NAME] [--seconds N] [--packets N] [--snaplen N] [--filter EXPR]` | `capture live [NAME|auto] [seconds] [packets] [snaplen] [filter]` | Capture a short window of real packets and decode it through a temporary PCAP removed afterward. |
| `spectre process top [--limit N]` | `process top [N]` | List the current top processes by resident memory, with their PIDs. Defaults to 10; accepts 1 to 32. |
| `spectre process inspect PID` | `process inspect PID` | Read metadata for one current process. Use `self` in place of a PID for SPECTRE's own process. |
| `spectre runtime resources PID` | `runtime resources PID|self` | Inspect a process's current open files and sockets through `lsof`. |
| `spectre runtime sample PID [--seconds N]` | `runtime sample PID|self [seconds]` | Sample call stacks with macOS `sample`. |
| `spectre runtime trace PID PATTERN [--seconds N]` | `runtime trace PID PATTERN [seconds]` | Trace matching function calls in another process with an installed Frida CLI. |
| `spectre intel status` | `intel status` | Show keyless and optional intelligence provider availability. |
| `spectre intel query PROVIDER KIND VALUE` | `intel query PROVIDER KIND VALUE` | Query a provider for one IP, domain, hash, or CVE. |
| `spectre intel enrich` | `intel enrich recent` | On the command line, inspect SPECTRE's executable and enrich its hash; in the workspace, pivot from retained binary and packet observations. |
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

## Live capture, disassembly, runtime, and intelligence

Run `spectre doctor` first to see which local tools are present. macOS typically provides `tcpdump`, `objdump`, `lsof`, and `sample` as system tools. A capture is a real observation of traffic on the selected interface:

```sh
spectre lan status
spectre capture live --interface en0 --seconds 4 --packets 256
```

Replace `en0` with the interface shown by `lan status`, or omit `--interface` to use the detected interface. The defaults are four seconds, at most 256 packets, a 1,536-byte snap length, and the `ip or ip6` filter. You can change the filter with `--filter 'tcp port 443'`. Capture currently runs on macOS and Linux and requires permission to open the interface. If the one-shot command reports a BPF or permission error on macOS, use `sudo "$HOME/.cargo/bin/spectre" capture live --interface en0 --seconds 4` for that capture. The raw packet bytes go into a private temporary PCAP for decoding and are removed afterward; the resulting events are printed by a one-shot command or retained by a running workspace. The classic PCAP decoder does not reassemble TCP streams or decode encrypted payloads.

Disassembly reads a local binary and emits instruction, address, and branch/call/return observations from its first executable section. It needs a local `objdump` and does not run the target program:

```sh
spectre disassemble /bin/ls --instructions 96
```

On macOS, `xcode-select --install` installs the Xcode Command Line Tools if `objdump` is missing. The instruction limit is 1 to 256; the input file limit is 64 MiB. Universal Mach-O files prefer the current machine's architecture slice.

Runtime commands use a PID from `spectre process top`. `resources` and `sample` also accept `self` for SPECTRE's own process; tracing requires another PID:

```sh
spectre runtime resources 1234
spectre runtime sample 1234 --seconds 2
spectre runtime trace 1234 'open*' --seconds 5
```

`resources` reads up to 48 file/socket entries through `lsof`. `sample` uses macOS `sample(1)` for up to ten seconds and summarizes stack frames. `trace` uses an installed `frida-trace` for up to 20 seconds, attaches to another named PID, and retains at most 96 call lines. `runtime trace self` is rejected because tracing SPECTRE's own event loop can disrupt the workspace. Frida is optional; its [installation guide](https://frida.re/docs/installation/) covers `frida-tools`, and macOS can ask for permission to attach to a process. Protected processes may deny attachment. The default Assisted run uses `resources self` and a one-second sample; it does not start a Frida trace on its own.

Two intelligence sources work without keys: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for CVE IDs and [CIRCL hashlookup](https://github.com/adulau/hashlookup-server) for known-file hashes. Query them explicitly:

```sh
spectre intel status
spectre intel query cisa cve CVE-2021-44228
spectre intel query circl hash 8ED4B4ED952526D89899E723F3488DE4
```

For additional reports, set the relevant key in the terminal where you launch SPECTRE:

```sh
export SPECTRE_VT_API_KEY='your-virustotal-key'
export SPECTRE_ABUSEIPDB_API_KEY='your-abuseipdb-key'
spectre intel query auto ip 8.8.8.8
spectre intel query auto domain example.org
```

These `export` commands affect only that terminal session. To use the keys from future terminal windows, add the exports to your shell startup file (on a default Mac shell, `~/.zshrc`) or load them from a secret manager. Keep keys out of the repository.

VirusTotal accepts public IP, domain, and MD5/SHA-1/SHA-256 hash queries; AbuseIPDB accepts public IPs. `auto` queries each configured provider that supports the indicator. It never uploads a local file: only the indicator value is sent. Providers can receive and retain queried values, and their reports are context, not proof. In particular, a CIRCL known-file match is not a malware or safety verdict. Within one running SPECTRE process, reports are cached for 15 minutes and the CISA catalog for one hour. Requests have an eight-second timeout, and provider rate-limit responses are reported; [VirusTotal's public API quota](https://docs.virustotal.com/reference/public-vs-premium-api) applies to public keys. From a fresh terminal, `spectre intel enrich` first inspects SPECTRE's own executable, then queries its SHA-256 and prints the intelligence events. In the running workspace, `intel enrich recent` uses the latest retained SHA-256 plus up to two distinct non-local public peers from recent packet observations when an IP provider key is present. Assisted F6 runs this pivot after its binary, packet, and disassembly stages.

## Workspace keys

| Key | Action |
| --- | --- |
| `F1` | Open or close help. |
| `F2` | Cycle autonomous, interactive, and assisted input modes. |
| `F3` | In Assisted, browse scenes. The selected scene stays pinned for 30 seconds, then automatic changes resume if enabled. |
| `F4` | Cycle the four themes. |
| `F5` | Open workspace settings. |
| `F6` in assisted mode | Run every stage of the selected built-in session with one key and start ongoing live follow-ups. The first/default session includes a real LAN survey when LAN assessment is on. |
| `F7` in assisted mode | Pause or resume ongoing Assisted follow-ups. |
| `F8` in assisted mode | Turn automatic scene changes on or off. Analysis continues while scenes are held. |
| `Up` / `Down` or `PageUp` / `PageDown` in assisted mode | Scroll the current scene by one row or ten rows. Scrolling holds that scene for 30 seconds. |
| `Tab` / `Shift+Tab` in assisted mode | Select the next or previous built-in or custom scenario. |
| `Left` in assisted mode | Return to the previous stage and reset its prepared input. |
| `Enter` in assisted mode | After a full reveal, run a local built-in step; record and advance an active network or custom step without running it. |
| `Ctrl+R` in assisted mode | Explicitly run a fully revealed active step in a network scenario. |
| `Ctrl+J` / `Ctrl+K` | Select newer or older observation. |
| `PageDown` / `PageUp` outside assisted mode | Move selection by ten observations. |
| `/` in autonomous mode | Open interactive command input. |
| `Up` / `Down` in interactive mode | Recall command history. |
| `Enter` in interactive mode | Submit the typed command. |
| `Esc` in interactive mode | Clear input and return to autonomous input. |
| `Ctrl+C` | Exit. |

The settings panel currently changes profile (`p`), theme (`t`), view arrangement (`l`), refresh interval (`r`), local autonomous collection (`a`), and LAN assessment (`n`). Profile, theme, refresh, autonomous, and LAN settings are saved. Turning LAN assessment off omits the LAN stages from the default Assisted session, stops future LAN follow-ups, and hides the dedicated LAN scenario; local stages and follow-ups still run. The arrangement applies to the current workspace session. The terminal must be at least 48 columns by 10 rows; scenes adapt to the available width.

### Assisted scenarios

No user-authored plan is needed. Press `F2` until **ASSISTED** appears. It opens on **System and network** and builds scenes from observations already present. Mission, Network, Processes, Traffic, Binaries, and Signals are the starting views. Host and binary dossiers, Packets, Runtime, Disassembly, and Threat Intel join the rotation when their evidence arrives. Entering Assisted only displays existing evidence. Press `F6` to run the complete session. With LAN assessment on, its 16 stages cover `doctor`, modules, interface traffic, a short live packet window, process inventory and resources, a call-stack sample, binary inspection and disassembly, an intelligence pivot from observed indicators, indicator review, LAN context and survey, and final triage. With LAN assessment off, the three LAN stages are omitted, leaving 13 stages. The packet window requires capture permission; optional tools and provider keys affect their respective stages. A failed stage reports an error while the other stages continue. The LAN survey makes real TCP and selected HTTP(S) requests when enabled.

After any built-in F6 run, Assisted stays live: it refreshes live packets, process resources, process inventory, and interface traffic about every 20 seconds. It repeats a one-second stack sample every third follow-up and the intelligence pivot every sixth. A recurring LAN survey is scheduled no more than once every 120 seconds only after an F6 run of **System and network** or **Local network**, and only while LAN assessment stays on. Other scenarios do not acquire recurring active scans. Follow-ups do not pile up while a previous request is still running. Leaving Assisted pauses scheduling. `F7` pauses or resumes future follow-ups after the first F6 run; an in-flight request can finish. `F8` controls automatic scene changes without stopping analysis. `F3` browses scenes and holds the selected one for 30 seconds before automatic changes resume. Up/Down and PageUp/PageDown scroll the selected scene and also hold it for 30 seconds. Automatic revisits advance through longer evidence lists. A new LAN host, open endpoint, or indicator match can bring its relevant scene into focus. Automatic display changes also draw on ongoing local collection; they do not imply a new probe was sent. The footer shows the current scene and activity state.

The focused **Local research** scenario has seven stages: Environment (`doctor`), Collection (`module list`), Interface traffic (`traffic snapshot`), Initial triage (`triage`), Binary inspection, Indicators (`indicator list`), and Final review (`triage`). Binary inspection prefers SPECTRE's executable when it fits the 64 MiB analyzer limit and otherwise uses a small real platform executable. Background local collection continues during an Assisted run. Each stage uses the same commands and evidence as interactive mode.

The separate process investigation scenario has three stages: `process top`, `process inspect self`, and `triage`. It reads current processes and inspects the running SPECTRE process as a concrete starting point. Select it with `Tab` and press `F6` to run the sequence. To inspect another PID, use `spectre process inspect PID` or the interactive prompt.

Each ordinary character key reveals the next character of the prepared input, regardless of the key pressed. Backspace retracts one character; Escape resets the current step; Left revisits the previous stage. After a local built-in command is fully revealed, Enter runs it and advances when the result arrives. If the step fails, it stays in place and Enter retries it. The resulting observations appear in the normal event stream. Enter does nothing until the current input is fully revealed.

Use `Tab` and `Shift+Tab` to switch scenarios. When LAN assessment is enabled, a local-network scenario is available. It detects the private IPv4 interface and shows the selected range when one is found. Its four stages are Network context (`lan status`), Host and service survey (`lan survey CIDR`), Survey review (`lan report`), and Final triage (`triage`). If no suitable interface is available, the context step reports that and the survey cannot run. A separate scoped network scenario appears for each exact target added to `allowed_targets`, for example with `scope add 192.168.1.1` in interactive mode. `F6` runs the selected exact-target sequence too. Select the scenario and check the displayed target or range before pressing `F6`; that key starts all active stages in the selected built-in session. No network survey starts merely by launching SPECTRE or switching to Assisted mode.

For manual stage-by-stage use, local review steps run on Enter after a full reveal. Active capture, intelligence, LAN survey, scan, investigation, and HTTP steps must be fully revealed and then run with `Ctrl+R`. Enter alone records and advances an active step without making the request. The exact-target scenario still enforces its configured target. Use `F5`, then `n`, or `lan on|off` at the interactive prompt to toggle the local-network session; the toggle does not alter exact-target scope.

Custom sequences remain available. In interactive mode, enter the following, then return to assisted mode and select the custom scenario with `Tab`:

```text
workflow add "binary /path/to/program"
workflow add "pcap /path/to/capture.pcap"
workflow list
```

For a custom step, Enter after the full reveal records a `prepared.input` event with `prepared` provenance and advances. Custom text is **never executed**. Use `workflow remove 2` or `workflow clear` to edit the sequence. Entries are saved in `prepared_workflow` in the configuration, with at most 256 steps and 4,096 bytes per step. Recorded prepared input is included in a JSON Lines export if it remains in memory. To run a custom command, switch to interactive mode and enter it there.

Assisted mode runs built-in actions and presents their observed results; it is not an AI assistant or a shell. Custom prepared text is still presentation-only. To change the event limit from the interactive prompt, use `retention set 5000`; the workspace display adopts it immediately, and the event hub adopts it on the next launch.

## Configuration

Run `spectre configure` to locate the platform-specific configuration file. The current keys are:

| Key | Default | Meaning |
| --- | --- | --- |
| `profile` | Recommended on first run | One of the bundled local collection presets or `custom`. |
| `theme` | `intelligence` | `intelligence`, `arctic`, `amber`, or `monochrome`. |
| `refresh_ms` | `500` | Terminal refresh interval; validated from 100 to 10,000 ms. |
| `retention_events` | `2000` | Maximum in-memory event history; validated from 100 to 100,000. |
| `autonomous` | `true` | Start local collection when launching the workspace. |
| `lan_assessment_enabled` | `true` | Include the LAN survey in the default combined Assisted session and make the dedicated LAN scenario available. Entering Assisted does not probe; F6 on either LAN scenario starts the first survey, and follow-ups can repeat it no more than once every 120 seconds while Assisted remains active. |
| `allowed_targets` | `[]` | Exact-match hosts or IP strings for active commands. |
| `enabled_modules` | Selected by first-run profile | Local modules to run. `traffic` samples interface counters; `binary` enables bounded baseline and follow-up inspection of observed process executables and requires `process`; `correlation` enables subject links. |
| `prepared_workflow` | `[]` | Optional custom assisted presentation entries. Built-in scenarios are available when this is empty. |
| `indicators` | `[]` | Exact SHA-256, domain, and IP values evaluated against supported observations. |

`doctor` checks process inspection, passive interface counters, and whether a suitable private LAN segment can be detected without sending probes. It also lists local tools. `tcpdump`, `objdump`, `lsof`, and macOS `sample` back the capture, disassembly, and runtime commands when present; `frida-trace` adds optional function tracing. TShark, nmap, and Ghidra are discovery entries rather than analyzer dependencies. A missing tool affects its own operation and appears as a command error.

Bundled profiles are `local-research` (host, process, traffic, correlation, and a small executable baseline), `binary-monitor` (the same modules with a larger binary budget), `focused` (process and correlation), and `offline` (no autonomous collection). `custom` preserves the current module selection. On first run, SPECTRE recommends `binary-monitor` when it detects at least 8 GiB of RAM and `local-research` otherwise. If memory inspection is unavailable, it uses `local-research`. `spectre doctor` reports the recommendation. Selecting a profile saves its settings and updates the running collector in the workspace.

With `local-research`, the collector selects up to 16 executables from the initial process inventory, including SPECTRE's own executable when available. It remembers at most 64 distinct paths, queues at most 64 pending paths, and runs one binary analysis at a time. `binary-monitor` raises those limits to 128 initial executables, 512 distinct paths, 256 pending paths, and two analysis slots. Both profiles analyze at most one baseline path per five-second interval; newly observed process executables may also be inspected. Autonomous inspection publishes compact identity, summary, and notable-finding events to keep the live stream readable. `spectre analyze binary PATH` or the workspace `binary PATH` command still returns the detailed sections, imports, symbols, and strings for an explicit investigation. Once the baseline queue is empty, one watched path is checked per interval for a changed size or modification time. A change can trigger reanalysis; the check does not prove the file content changed and is not a full filesystem integrity scan.

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

The matcher checks specific fields: binary SHA-256 identity/container hashes and disassembly summary SHA-256; offline PCAP and live-capture DNS questions, TLS SNI, HTTP Host, and flow source/destination IPs; HTTP response hosts; resolved IP addresses on exact-target open TCP observations; and addresses in LAN host and open-port observations. A domain indicator matches the complete hostname, not a subdomain or substring. A match creates a `derived` event with the source event ID, timestamp, matched field, indicator kind/value/label, and medium triage severity. It records an exact relationship between a configured value and an observation. It is not a malware verdict, reputation check, or vulnerability finding. Prepared text and derived events are not matched. Configuring an indicator does not perform network activity or change authorized target scope.

## Evidence and limits

Events include a `source` field and evidence origins. File analysis outputs reference the file path; network events reference the request or connection that produced them. Correlation links events by matching subject strings and lists their event IDs. Indicator matches link a configured value to a specific observed field. These derived events are navigation and triage aids, not independent proof of a security issue.

The current export contains only events retained in memory for the running workspace. `export PATH` creates a new file and refuses to replace an existing path. Exported JSON Lines can include local paths, process names, target addresses, HTTP headers, packet metadata, configured indicator values, and prepared input text. Review the file before sharing it. Binary analysis is limited to 64 MiB files. Classic PCAP analysis is limited to 512 MiB and 200,000 packets; PCAPNG is not yet accepted. HTTP inspection does not follow redirects, and its header observations describe one response rather than an entire site. The LAN survey covers one selected private IPv4 segment of at most /24 size, not other local interfaces, VLANs, IPv6 networks, or networks beyond that segment. Its TCP observations are evidence of responses to the selected probes, not a complete device inventory.
