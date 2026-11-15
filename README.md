# SPECTRE

Terminal intelligence and security research environment

Created by Cade Masterson

[Two-page Mac quick-start sheet](docs/SPECTRE-Quick-Start.pdf)

SPECTRE brings local observations, offline artifact analysis, and explicitly scoped network assessment into one terminal workspace. Its event stream retains the evidence behind each observation. The current codebase is an early working foundation, with a focused set of analyzers and a shared interface for autonomous and hands-on work.

## What works today

| Area | Current capability |
| --- | --- |
| Local observation | Periodic host samples, process starts and inventory, per-interface traffic counters when enabled, and compact dossiers for observed executables when the binary module is enabled. |
| Process investigation | A live top-process snapshot by resident memory and inspection of a selected PID, including memory, status, timing, and executable path when available. |
| Binary analysis | PE, ELF, and Mach-O identity, SHA-256, sections and entropy, imports, linked libraries, exports, symbols, and bounded printable strings. |
| Packet analysis | Offline classic PCAP parsing, flow counts, DNS questions, TLS ClientHello SNI, and HTTP Host observations. |
| Live packet capture | A short macOS or Linux capture from a named local interface through `tcpdump`, decoded by the same PCAP analyzer. The temporary capture is removed after the observation. |
| Network assessment | A real TCP survey of the selected private IPv4 interface's directly connected segment, capped at /24, with HTTP follow-up on observed open web ports. Exact-target scans have bounded concurrency and passive banner capture. |
| Disassembly | Bounded instruction and control-flow observations from a local PE, ELF, or Mach-O executable section through a local disassembler. The binary is not run. |
| Runtime inspection | Current process file/socket resources through `lsof`, call-stack samples through macOS `sample`, and optional function tracing of another PID through an installed Frida CLI. |
| External intelligence | Explicit CISA KEV CVE and CIRCL hash lookups without API keys; optional VirusTotal IP/domain/hash and AbuseIPDB IP reports with provider keys. Results retain provider and source URLs. |
| HTTP assessment | One scoped HTTP(S) response, including headers, cookie attributes, and HSTS observations. Redirects are not followed. |
| Indicator matching | User-configured SHA-256, domain, and IP values matched against binary/disassembly hashes, offline or live packet observations, and supported network fields, with source event references. |
| Investigation | A bounded event history, evidence inspection, subject links across modules, profile presets, and JSON Lines export. |
| Terminal workspace | Evidence-driven Mission, Network, Processes, Traffic, Binaries, and Signals scenes in Assisted mode; Packets, Runtime, Disassembly, Threat Intel, host, and binary dossier screens join as observations arrive. Four themes and separate autonomous and interactive modes. |

The [roadmap](docs/ROADMAP.md) tracks deeper packet decoding, instrumentation, intelligence, a plugin API, and packaged releases separately from these working entry points.

## Install and start

Use a current stable Rust toolchain on macOS, Linux, or Windows. From this repository:

```sh
cargo install --path . --locked --force
spectre doctor
spectre profiles
spectre
```

On macOS or Linux, if the shell reports `spectre: command not found` after installation, run `~/.cargo/bin/spectre` or add `~/.cargo/bin` to your `PATH`.

`spectre` opens the terminal workspace when standard input and output are attached to a terminal. On first launch it chooses a local profile from detected memory, then writes the configuration. Systems with at least 8 GiB of RAM start with `binary-monitor`; other systems use `local-research`. Both profiles inspect real executables from the local process baseline, including SPECTRE itself when available. `local-research` uses a smaller queue and one analysis slot; `binary-monitor` covers more paths with two slots. Each profile then watches its bounded set of executable paths for metadata changes. Local observation starts automatically. An explicit `spectre analyze binary PATH` request still returns the full detailed analysis.

The source build is the installation method at present. Precompiled packages and release installers have not been published. CI checks macOS, Linux, and Windows.

Use `spectre profiles`, `spectre themes`, `spectre modules`, and `spectre indicators` to inspect the current configuration. `spectre version` displays the installed version and creator attribution.

`spectre doctor` shows which local capabilities are available, including process inspection, interface counters, and the detected private LAN segment. It does not start a survey.

External lookups use one indicator at a time. CISA KEV CVE and CIRCL known-file hash lookups need no key:

```sh
spectre intel status
spectre intel query cisa cve CVE-2021-44228
spectre intel query circl hash 8ED4B4ED952526D89899E723F3488DE4
```

VirusTotal reports for public IPs, domains, and hashes need `SPECTRE_VT_API_KEY`; AbuseIPDB IP reports need `SPECTRE_ABUSEIPDB_API_KEY`. These are optional environment variables. From a new terminal, `spectre intel enrich` inspects SPECTRE's own executable and looks up its SHA-256. Inside a running workspace, `intel enrich recent` pivots from the latest retained binary hash and up to two public peers observed in packet capture when IP provider keys are set. No file is uploaded. CIRCL identifies hashes present in a known-file corpus; a hit or miss is not a malware verdict.

`spectre traffic snapshot` reads real cumulative byte totals for nonloopback interfaces. When the `traffic` module is enabled, SPECTRE also samples byte and packet counter changes during local collection. These counters describe aggregate traffic for an interface; they do not contain packet contents, destinations, or per-process attribution.

## A short investigation

Offline inspection needs no target scope:

```sh
spectre analyze binary /path/to/program
spectre analyze pcap /path/to/capture.pcap
spectre disassemble /path/to/program --instructions 96
```

For a current process snapshot, run:

```sh
spectre process top
spectre process inspect self
spectre process inspect 1234
```

Replace `1234` with a PID from `process top`. `self` selects the running SPECTRE process.

To capture and decode a few seconds of actual traffic on this computer:

```sh
spectre capture live --interface en0 --seconds 4 --packets 256
```

Replace `en0` with the interface reported by `spectre lan status`, or omit `--interface` to use the detected interface. Packet capture needs OS permission to open that interface. `spectre doctor` reports whether `tcpdump` is installed; it does not grant capture permission.

For current process resources and a short call-stack sample on macOS:

```sh
spectre runtime resources self
spectre runtime sample self --seconds 2
```

An installed `frida-trace` adds optional function tracing for another PID. macOS may deny attachment to a protected process. See [usage](docs/USAGE.md#live-capture-disassembly-runtime-and-intelligence) for commands and provider keys.

Add `--json` to a headless analysis command for complete JSON Lines output. The default text view limits long evidence lists for readability.

An exact indicator can be configured before analysis:

```sh
spectre indicators add domain example.org "research set"
spectre indicators
```

Matching is local and uses observed fields only, including live packet DNS, TLS SNI, HTTP Host, and flow addresses plus disassembly SHA-256. A match is a derived event that cites its source observation; it is not a malware verdict. Adding an indicator does not initiate a scan or expand target scope.

Network requests require an exact host or IP entry before they run:

```sh
spectre scope add 192.0.2.10
spectre scan 192.0.2.10 --ports 22,80,443
spectre investigate 192.0.2.10 --ports 22,80,443
spectre http http://192.0.2.10/
```

The addresses above are documentation examples. `scope add` records the target in the local configuration; it does not probe it. A scan uses only the ports supplied or the documented default set. `investigate` checks its selected ports and, when conventional web ports are open, makes bounded HTTP follow-ups pinned to the observed addresses. HTTP inspection makes one GET request and does not follow redirects.

To survey the current local network segment, run `spectre lan status` to see the selected interface and exact range, then `spectre lan survey` to make real TCP probes in that range. Open web ports can receive a bounded HTTP(S) follow-up. `spectre lan off` removes the LAN stages from the default session and disables the dedicated LAN survey; `spectre lan on` enables them again. Entering Assisted mode displays existing observations without starting a survey. Pressing `F6` on **System and network** or **Local network** starts a survey when LAN is enabled; ongoing follow-ups revisit the segment no more than once every 120 seconds while Assisted remains active. The survey reports hosts only when their TCP responses support that observation; a silent host may still be present.

Inside the workspace, press `/` for interactive command input and `F1` for the keyboard reference. `F2` cycles input modes while local collection continues. Assisted mode opens on **System and network** and shows scenes populated from real observations. Press `F6` to run the full session with one key. It collects host, process, traffic, and binary observations; attempts a short live packet capture and call-stack sample; disassembles a local executable section; enriches a few observed indicators; and surveys the current LAN when enabled. No user-authored plan is needed. The combined run has 16 stages with LAN enabled and 13 with it off. Capture, sampling, and enrichment stages report their own errors if OS access, an optional tool, or a provider key is missing; the rest of the session continues. After the first pass, Assisted refreshes live packets, process resources, process inventory, and interface traffic about every 20 seconds. It repeats a one-second stack sample every third follow-up and the intelligence pivot every sixth. For the two LAN scenarios with LAN enabled, it revisits the local segment no more than once every 120 seconds. Follow-ups pause when you leave Assisted. Scenes appear as evidence arrives and rotate automatically afterward. `F3` browses and holds a scene for 30 seconds; Up/Down scrolls; `F8` toggles automatic scene changes; `F7` pauses or resumes follow-ups. Press `F5`, then `n`, to toggle the LAN part. The `triage` command summarizes retained observations and links.

`Tab` selects focused local research, process investigation, local-network, or exact-target scenarios. For stage-by-stage use, passive review runs on Enter after a full reveal, and active network steps use `Ctrl+R`. An `F6` run performs the selected built-in session, including its active network steps. Custom prepared text can also be added, but it is only recorded, never executed. The scenes summarize observed data; they do not invent findings. See [usage](docs/USAGE.md) for controls and scope.

### Offline binary analysis session

![SPECTRE terminal workspace analyzing the macOS /bin/ls binary, with Mach-O identity and SHA-256 evidence](docs/assets/offline-binary.png)

Captured from the terminal workspace while inspecting `/bin/ls` with autonomous collection disabled. The [capture script](tools/capture_offline.py) reproduces the image from a PTY session on macOS.

## Design

Analyzers return structured events. An event has a timestamp, module, subject, severity, source type, and evidence entries with origins. A bounded hub stores recent events, links observations sharing a subject across modules, and broadcasts updates to the terminal workspace. The user interface displays analyzer output rather than generating technical findings.

[Architecture](docs/ARCHITECTURE.md) describes the data path, current boundaries, and extension work. [Contributing](CONTRIBUTING.md) covers development checks and evidence standards.

## Project status and licensing

SPECTRE is an early working foundation created and led by Cade Masterson. It is available under your choice of the [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) license. Third-party dependencies retain their own license terms. The [roadmap](docs/ROADMAP.md#licensing-and-release) tracks the work remaining before a tagged release and packaged binaries.
