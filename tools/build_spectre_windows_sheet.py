#!/usr/bin/env python3
# /// script
# dependencies = ["reportlab>=4,<5"]
# ///
"""Build the two-page Windows guide with `uv run tools/build_spectre_windows_sheet.py`."""

from __future__ import annotations

from pathlib import Path
from shutil import copyfile

from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas

from build_spectre_sheet import (
    BG,
    CYAN,
    H,
    LEFT,
    MUTED,
    PALE,
    RIGHT,
    SOFT,
    W,
    WIDTH,
    code,
    feature,
    panel,
    para,
    right,
    rule,
    section,
    text,
    y,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "SPECTRE-Windows-Quick-Start.pdf"
PUBLIC_COPY = ROOT / "docs" / "SPECTRE-Windows-Quick-Start.pdf"


def page_chrome(c: canvas.Canvas, kicker: str, page: int) -> None:
    c.setFillColor(BG)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(CYAN)
    c.rect(LEFT, y(25), 56, 2, fill=1, stroke=0)
    text(c, kicker, LEFT, 41, "Courier", 7.3, SOFT)
    right(c, "CADE MASTERSON", RIGHT, 41, "Courier", 7.3, SOFT)
    rule(c, 52)
    rule(c, 744)
    text(c, "SPECTRE  /  WINDOWS QUICK START", LEFT, 759, "Courier", 7.2, SOFT)
    right(c, f"0{page} / 02", RIGHT, 759, "Courier", 7.2, SOFT)


def first_page(c: canvas.Canvas) -> None:
    page_chrome(c, "PROJECT / WINDOWS INSTALL", 1)
    text(c, "SPECTRE", LEFT, 91, "Helvetica-Bold", 29, PALE)
    text(c, "Terminal intelligence and security research environment", LEFT, 111, "Helvetica", 10.1, MUTED)
    url = "https://github.com/CadeM4/SPECTRE"
    label = "github.com/CadeM4/SPECTRE"
    text(c, label, LEFT, 137, "Courier", 9.1, CYAN)
    c.linkURL(url, (LEFT, y(141), LEFT + pdfmetrics.stringWidth(label, "Courier", 9.1), y(128)), relative=0)
    rule(c, 150)

    section(c, "WHAT IT IS", 170)
    para(
        c,
        "I built SPECTRE to bring system activity, network checks, file analysis, and evidence into one terminal workspace. This sheet covers the native Windows build.",
        LEFT,
        188,
        WIDTH,
        size=9.25,
        leading=13.2,
        max_height=39,
    )

    section(c, "WHAT WORKS ON WINDOWS", 229)
    feature(c, LEFT, 240, "SYSTEM", "Live process inventory, host details, and interface traffic counters.")
    feature(c, LEFT + 272, 240, "NETWORK", "Checks the connected LAN and scoped TCP or HTTP targets when run.")
    feature(c, LEFT, 315, "FILES", "Inspects PE, ELF, and Mach-O files plus saved classic PCAP captures.")
    feature(c, LEFT + 272, 315, "THREAT INTEL", "Looks up CISA CVEs and CIRCL hashes; two keyed providers are optional.")

    section(c, "SET UP IN POWERSHELL / ONCE", 408)
    text(c, "01  Install Git and Rust", LEFT, 428, "Helvetica-Bold", 9.0, PALE)
    panel(c, 438, 49, accent=True)
    code(
        c,
        [
            "winget install --id Git.Git -e --source winget",
            "winget install --id Rustlang.Rustup -e --source winget",
        ],
        LEFT + 17,
        457,
        size=8.35,
        leading=14.5,
    )
    para(
        c,
        "Rust may prompt for Visual Studio C++ Build Tools. Accept it, including Desktop development with C++. This supplies the linker required to build SPECTRE.",
        LEFT,
        503,
        WIDTH,
        size=8.2,
        leading=11.4,
        color=MUTED,
        max_height=27,
    )

    text(c, "02  Close PowerShell, reopen it, then build", LEFT, 546, "Helvetica-Bold", 9.0, PALE)
    panel(c, 557, 100, accent=True)
    code(
        c,
        [
            "git --version; cargo --version",
            "cd $HOME",
            "git clone https://github.com/CadeM4/SPECTRE.git",
            "cd .\\SPECTRE",
            "cargo install --path . --locked --force",
            "spectre doctor",
        ],
        LEFT + 17,
        576,
        size=8.15,
        leading=14.0,
    )
    para(
        c,
        "No computer name or Windows username needs editing. The source goes in your own home folder. If Cargo reports that link.exe is missing, add Desktop development with C++ in Visual Studio Installer, then retry the install.",
        LEFT,
        675,
        WIDTH,
        size=8.15,
        leading=11.3,
        color=MUTED,
        max_height=45,
    )
    c.showPage()


def control_row(c: canvas.Canvas, top: float, key: str, description: str) -> None:
    text(c, key, LEFT + 17, top, "Courier-Bold", 8.8, CYAN)
    text(c, description, LEFT + 105, top, "Helvetica", 8.7, PALE)


def second_page(c: canvas.Canvas) -> None:
    page_chrome(c, "FIELD GUIDE / WINDOWS", 2)
    text(c, "USE SPECTRE", LEFT, 90, "Helvetica-Bold", 27.5, PALE)
    text(c, "Run the checks, then follow the evidence.", LEFT, 111, "Helvetica", 10.1, MUTED)

    section(c, "NEW POWERSHELL WINDOW / EVERY TIME", 145)
    panel(c, 157, 78, accent=True)
    text(c, "spectre", LEFT + 17, 184, "Courier-Bold", 13.1, PALE)
    text(c, "No cd or username edit needed.", LEFT + 118, 182, "Helvetica", 8.7, MUTED)
    text(c, "If not found:", LEFT + 17, 212, "Helvetica", 8.1, MUTED)
    text(c, '& "$env:USERPROFILE\\.cargo\\bin\\spectre.exe"', LEFT + 95, 212, "Courier", 8.15, PALE)

    section(c, "ASSISTED WORKSPACE", 257)
    panel(c, 269, 122, accent=True)
    for index, (key, description) in enumerate(
        [
            ("F2", "switch to ASSISTED"),
            ("F6", "run the full session and start live follow-ups"),
            ("F3", "browse a view; Up/Down scroll"),
            ("F7 / F8", "pause follow-ups / automatic view changes"),
            ("F5 then n", "turn the connected-LAN survey on or off"),
        ]
    ):
        control_row(c, 293 + index * 20, key, description)
    para(
        c,
        "F6 schedules 16 stages with LAN on, or 13 with it off. On Windows, unavailable capture and runtime stages report an error and the rest continue. Views rotate as evidence arrives.",
        LEFT,
        408,
        WIDTH,
        size=8.3,
        leading=11.4,
        color=MUTED,
        max_height=28,
    )

    section(c, "NATIVE WINDOWS / WHAT TO EXPECT", 454)
    panel(c, 466, 92, x=LEFT, width=256)
    panel(c, 466, 92, x=LEFT + 272, width=256)
    text(c, "WORKING", LEFT + 14, 486, "Courier-Bold", 8.2, CYAN)
    para(
        c,
        "Processes and traffic; LAN TCP/HTTP; static binaries and saved PCAPs; CISA and CIRCL lookups.",
        LEFT + 14,
        498,
        228,
        size=8.2,
        leading=11.2,
        max_height=56,
    )
    text(c, "PLATFORM LIMITS", LEFT + 286, 486, "Courier-Bold", 8.2, CYAN)
    para(
        c,
        "Live capture, stack sampling, Frida tracing, and lsof resources are unavailable natively. Disassembly needs objdump or llvm-objdump installed.",
        LEFT + 286,
        498,
        228,
        size=8.2,
        leading=11.2,
        max_height=56,
    )

    section(c, "RUN A SPECIFIC CHECK", 582)
    panel(c, 594, 111, x=LEFT, width=256, accent=True)
    panel(c, 594, 111, x=LEFT + 272, width=256, accent=True)
    text(c, "SYSTEM / NETWORK", LEFT + 14, 612, "Courier-Bold", 8.0, CYAN)
    text(c, "FILES / INTELLIGENCE", LEFT + 286, 612, "Courier-Bold", 8.0, CYAN)
    code(
        c,
        [
            "spectre process top",
            "spectre traffic snapshot",
            "spectre lan status",
            "spectre lan survey",
        ],
        LEFT + 14,
        631,
        size=7.4,
        leading=19,
        max_width=228,
    )
    code(
        c,
        [
            'spectre analyze binary "$env:WINDIR\\System32\\notepad.exe"',
            'spectre analyze pcap "$HOME\\Downloads\\capture.pcap"',
            "spectre intel status",
            "spectre intel query cisa cve CVE-2021-44228",
        ],
        LEFT + 286,
        631,
        size=6.6,
        leading=19,
        max_width=228,
    )
    para(
        c,
        "The PCAP path is an example: replace capture.pcap with your file. For VirusTotal and AbuseIPDB, add your own API keys; see the repo's usage guide.",
        LEFT,
        718,
        WIDTH,
        size=7.5,
        leading=9.4,
        color=MUTED,
        max_height=20,
    )
    c.showPage()


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(OUTPUT), pagesize=(W, H), pageCompression=1)
    c.setTitle("SPECTRE | Windows Quick Start")
    c.setAuthor("Cade Masterson")
    c.setSubject("SPECTRE Windows setup, Assisted workspace, and platform availability")
    c.setCreator("SPECTRE")
    first_page(c)
    second_page(c)
    c.save()
    copyfile(OUTPUT, PUBLIC_COPY)
    print(OUTPUT)


if __name__ == "__main__":
    main()
