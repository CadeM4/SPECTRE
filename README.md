# SPECTRE

Terminal intelligence and security research environment

Created by Cade Masterson

SPECTRE brings local observations, offline artifact analysis, and explicitly scoped network assessment into one terminal workspace. Its event stream retains the evidence behind each observation. The current codebase is an early working foundation, with a focused set of analyzers and a shared interface for autonomous and hands-on work.

## What works today

| Area | Current capability |
| --- | --- |
| Local observation | Periodic host samples, process starts, process inventory, and bounded inspection of observed executables when the binary module is enabled. |
| Binary analysis | PE, ELF, and Mach-O identity, SHA-256, sections and entropy, imports, linked libraries, exports, symbols, and bounded printable strings. |
| Packet analysis | Offline classic PCAP parsing, flow counts, DNS questions, TLS ClientHello SNI, and HTTP Host observations. |
| Network assessment | TCP connect checks against an exact configured target, with bounded concurrency and passive banner capture. A scoped investigation can follow observed web ports with HTTP inspection. |
| HTTP assessment | One scoped HTTP(S) response, including headers, cookie attributes, and HSTS observations. Redirects are not followed. |
| Indicator matching | User-configured SHA-256, domain, and IP values matched against supported observation fields, with source event references. |
| Investigation | A bounded event history, evidence inspection, subject links across modules, profile presets, and JSON Lines export. |
| Terminal workspace | Responsive overview, timeline, and evidence views; four themes; autonomous and interactive modes, plus built-in assisted scenarios. |

SPECTRE does not yet include live packet capture, disassembly, runtime instrumentation, external threat intelligence, a plugin API, or binary releases. The [roadmap](docs/ROADMAP.md) tracks those directions separately from implemented behavior.

## Install and start

Use a current stable Rust toolchain on macOS, Linux, or Windows. From this repository:

```sh
cargo install --path . --locked
spectre doctor
spectre profiles
spectre
```

On macOS or Linux, if the shell reports `spectre: command not found` after installation, run `~/.cargo/bin/spectre` or add `~/.cargo/bin` to your `PATH`.

`spectre` opens the terminal workspace when standard input and output are attached to a terminal. On first launch it chooses a local profile from detected memory, then writes the configuration. Systems with at least 8 GiB of RAM start with `binary-monitor`; other systems use `local-research`. Both profiles inspect real executables from the local process baseline, including SPECTRE itself when available. `local-research` uses a smaller queue and one analysis slot; `binary-monitor` covers more paths with two slots. Each profile then watches its bounded set of executable paths for metadata changes. Local observation starts automatically. It does not scan external targets in the background.

The source build is the installation method at present. Precompiled packages and release installers have not been published. The project is tested locally on macOS; the CI workflow is intended to check Linux and Windows as well.

Use `spectre profiles`, `spectre themes`, `spectre modules`, and `spectre indicators` to inspect the current configuration. `spectre version` displays the installed version and creator attribution.

## A short investigation

Offline inspection needs no target scope:

```sh
spectre analyze binary /path/to/program
spectre analyze pcap /path/to/capture.pcap
```

Add `--json` to a headless analysis command for complete JSON Lines output. The default text view limits long evidence lists for readability.

An exact indicator can be configured before analysis:

```sh
spectre indicators add domain example.org "research set"
spectre indicators
```

Matching is local and uses observed fields only. A match is a derived event that cites its source observation; it is not a malware verdict. Adding an indicator does not initiate a scan or expand target scope.

Network requests require an exact host or IP entry before they run:

```sh
spectre scope add 192.0.2.10
spectre scan 192.0.2.10 --ports 22,80,443
spectre investigate 192.0.2.10 --ports 22,80,443
spectre http http://192.0.2.10/
```

The addresses above are documentation examples. `scope add` records the target in the local configuration; it does not probe it. A scan uses only the ports supplied or the documented default set. `investigate` checks its selected ports and, when conventional web ports are open, makes bounded HTTP follow-ups pinned to the observed addresses. HTTP inspection makes one GET request and does not follow redirects.

Inside the workspace, press `/` for interactive command input and `F1` for the keyboard reference. `F2` cycles input modes while local collection continues. Assisted mode includes a six-stage local investigation without requiring a user-authored plan. Press `F6` in assisted mode to run the entire local session with one key, or reveal each prepared command by typing and run it with Enter. The stages are Environment, Collection, Initial triage, Binary inspection, Indicators, and Final review. The `triage` command summarizes retained observation counts, recent subjects, indicator matches, correlation links, and latest observation IDs.

Each configured exact target has a selectable scoped network scenario. `Tab` and `Shift+Tab` switch scenarios. Passive local review steps run on Enter after a full reveal; active network steps require an explicit `Ctrl+R` and still obey scope limits. Custom prepared text can also be added, but it is only recorded, never executed. Assisted mode is a deterministic presentation workflow, not an AI assistant. See [usage](docs/USAGE.md) for controls and scope.

### Offline binary analysis session

![SPECTRE terminal workspace analyzing the macOS /bin/ls binary, with Mach-O identity and SHA-256 evidence](docs/assets/offline-binary.png)

Captured from the terminal workspace while inspecting `/bin/ls` with autonomous collection disabled. The [capture script](tools/capture_offline.py) reproduces the image from a PTY session on macOS.

## Design

Analyzers return structured events. An event has a timestamp, module, subject, severity, source type, and evidence entries with origins. A bounded hub stores recent events, links observations sharing a subject across modules, and broadcasts updates to the terminal workspace. The user interface displays analyzer output rather than generating technical findings.

[Architecture](docs/ARCHITECTURE.md) describes the data path, current boundaries, and extension work. [Contributing](CONTRIBUTING.md) covers development checks and evidence standards.

## Project status and licensing

SPECTRE is an early working foundation created and led by Cade Masterson. It is available under your choice of the [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) license. Third-party dependencies retain their own license terms. The [roadmap](docs/ROADMAP.md#licensing-and-release) tracks the work remaining before a tagged release and packaged binaries.
