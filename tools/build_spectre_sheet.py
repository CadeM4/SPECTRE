#!/usr/bin/env python3
# /// script
# dependencies = ["reportlab>=4,<5"]
# ///
"""Build the two-page SPECTRE quick-start sheet with `uv run tools/build_spectre_sheet.py`."""

from __future__ import annotations

from html import escape
from pathlib import Path
from shutil import copyfile

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "SPECTRE-Quick-Start.pdf"
PUBLIC_COPY = ROOT / "docs" / "SPECTRE-Quick-Start.pdf"
W, H = 612, 792
LEFT, RIGHT = 42, 570
WIDTH = RIGHT - LEFT

BG = colors.HexColor("#081118")
SURFACE = colors.HexColor("#0D1B24")
SURFACE_ALT = colors.HexColor("#10232D")
RULE = colors.HexColor("#305360")
CYAN = colors.HexColor("#41D1CF")
PALE = colors.HexColor("#D8E9EE")
MUTED = colors.HexColor("#9CB6C0")
SOFT = colors.HexColor("#7895A0")


def y(top: float) -> float:
    return H - top


def text(c: canvas.Canvas, value: str, x: float, top: float, font: str, size: float, color) -> None:
    c.setFont(font, size)
    c.setFillColor(color)
    c.drawString(x, y(top), value)


def right(c: canvas.Canvas, value: str, x: float, top: float, font: str, size: float, color) -> None:
    c.setFont(font, size)
    c.setFillColor(color)
    c.drawRightString(x, y(top), value)


def para(
    c: canvas.Canvas,
    value: str,
    x: float,
    top: float,
    width: float,
    *,
    size: float = 9.2,
    leading: float = 13.4,
    color=PALE,
    max_height: float = 100,
) -> float:
    style = ParagraphStyle(
        "sheet",
        fontName="Helvetica",
        fontSize=size,
        leading=leading,
        textColor=color,
        alignment=TA_LEFT,
        splitLongWords=False,
        spaceBefore=0,
        spaceAfter=0,
    )
    block = Paragraph(escape(value), style)
    _, height = block.wrap(width, max_height)
    assert height <= max_height, f"paragraph overflows: {value[:80]}"
    block.drawOn(c, x, y(top + height))
    return height


def panel(c: canvas.Canvas, top: float, height: float, *, x: float = LEFT, width: float = WIDTH, accent: bool = False) -> None:
    c.setFillColor(SURFACE_ALT if accent else SURFACE)
    c.setStrokeColor(RULE)
    c.setLineWidth(0.65)
    c.rect(x, y(top + height), width, height, fill=1, stroke=1)
    if accent:
        c.setFillColor(CYAN)
        c.rect(x, y(top + height), 3, height, fill=1, stroke=0)


def code(c: canvas.Canvas, lines: list[str], x: float, top: float, *, size: float = 8.5, leading: float = 14.5, max_width: float = 470) -> None:
    for index, line in enumerate(lines):
        assert pdfmetrics.stringWidth(line, "Courier", size) <= max_width, line
        text(c, line, x, top + index * leading, "Courier", size, PALE)


def section(c: canvas.Canvas, label: str, top: float) -> None:
    text(c, label, LEFT, top, "Courier-Bold", 9.0, CYAN)


def rule(c: canvas.Canvas, top: float) -> None:
    c.setStrokeColor(RULE)
    c.setLineWidth(0.6)
    c.line(LEFT, y(top), RIGHT, y(top))


def page_chrome(c: canvas.Canvas, kicker: str, page: int) -> None:
    c.setFillColor(BG)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(CYAN)
    c.rect(LEFT, y(25), 56, 2, fill=1, stroke=0)
    text(c, kicker, LEFT, 41, "Courier", 7.3, SOFT)
    right(c, "CADE MASTERSON", RIGHT, 41, "Courier", 7.3, SOFT)
    rule(c, 52)
    rule(c, 744)
    text(c, "SPECTRE  /  QUICK START", LEFT, 759, "Courier", 7.2, SOFT)
    right(c, f"0{page} / 02", RIGHT, 759, "Courier", 7.2, SOFT)


def feature(c: canvas.Canvas, x: float, top: float, title: str, description: str) -> None:
    width = 256
    panel(c, top, 65, x=x, width=width)
    text(c, title, x + 14, top + 20, "Courier-Bold", 8.1, CYAN)
    para(c, description, x + 14, top + 30, width - 28, size=8.45, leading=11.0, max_height=29)


def first_page(c: canvas.Canvas) -> None:
    page_chrome(c, "PROJECT / SOURCE INSTALL", 1)
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
        "I built SPECTRE to turn live activity on my Mac, packet captures, binaries, and network checks into one readable investigation. Every result keeps its source and evidence close by.",
        LEFT,
        188,
        WIDTH,
        size=9.25,
        leading=13.2,
        max_height=39,
    )

    section(c, "WHAT IT DOES", 229)
    feature(c, LEFT, 240, "LIVE COLLECTION", "Watches processes and interface traffic, captures real packets, and surveys the connected LAN.")
    feature(c, LEFT + 272, 240, "FILES + CODE", "Inspects PE, ELF, and Mach-O files, reads PCAPs, and disassembles executable instructions.")
    feature(c, LEFT, 315, "RUNTIME", "Samples call stacks and open resources. Frida can trace functions in a selected running PID.")
    feature(c, LEFT + 272, 315, "THREAT INTEL", "Checks CVEs with CISA and hashes with CIRCL. VirusTotal and AbuseIPDB work with API keys.")

    section(c, "SET UP ON A MAC / ONCE", 407)
    text(c, "01  Get the source", LEFT, 429, "Helvetica-Bold", 9.0, PALE)
    panel(c, 439, 58, accent=True)
    code(c, ["cd ~", "git clone https://github.com/CadeM4/SPECTRE.git", "cd SPECTRE"], LEFT + 17, 458, size=8.5, leading=14)
    text(c, "Already have the folder? Use cd ~/SPECTRE. The ~ means your own home folder.", LEFT, 511, "Helvetica", 8.3, MUTED)

    text(c, "02  Install and check it", LEFT, 537, "Helvetica-Bold", 9.0, PALE)
    panel(c, 547, 79, accent=True)
    code(
        c,
        [
            "cargo install --path . --locked --force",
            "echo 'export PATH=\"$HOME/.cargo/bin:$PATH\"' >> ~/.zshrc",
            "source ~/.zshrc",
            "spectre doctor",
        ],
        LEFT + 17,
        566,
        size=8.45,
        leading=14,
    )
    text(c, "If cargo is missing, install Rust from rust-lang.org/tools/install first.", LEFT, 639, "Helvetica", 8.3, MUTED)

    panel(c, 659, 66, accent=True)
    text(c, "NEW TERMINAL WINDOW / EVERY TIME", LEFT + 17, 679, "Courier-Bold", 8.25, CYAN)
    text(c, "spectre", LEFT + 17, 703, "Courier-Bold", 13.1, PALE)
    text(c, "Open Terminal and run this. No cd or username edit needed.", LEFT + 119, 701, "Helvetica", 8.4, MUTED)
    text(c, "If it says command not found: ~/.cargo/bin/spectre", LEFT + 17, 718, "Helvetica", 8.2, MUTED)
    c.showPage()


def screen_row(c: canvas.Canvas, x: float, top: float, name: str, detail: str) -> None:
    text(c, name, x, top, "Courier-Bold", 7.9, CYAN)
    text(c, detail, x + 94, top, "Helvetica", 7.7, PALE)


def second_page(c: canvas.Canvas) -> None:
    page_chrome(c, "FIELD GUIDE / MACOS", 2)
    text(c, "USE SPECTRE", LEFT, 90, "Helvetica-Bold", 27.5, PALE)
    text(c, "Start the session. Follow what it actually finds.", LEFT, 111, "Helvetica", 10.1, MUTED)

    section(c, "START A LIVE INVESTIGATION", 145)
    panel(c, 158, 108, accent=True)
    text(c, "F2", LEFT + 17, 183, "Courier-Bold", 11.2, CYAN)
    text(c, "switch to ASSISTED", LEFT + 60, 183, "Helvetica-Bold", 9.4, PALE)
    text(c, "F6", LEFT + 17, 214, "Courier-Bold", 11.2, CYAN)
    text(c, "run the full session and start live follow-ups", LEFT + 60, 214, "Helvetica-Bold", 9.4, PALE)
    para(
        c,
        "The first pass covers real packets, processes, call stacks, a binary, disassembly, intelligence, and the connected LAN. It runs 16 stages with LAN on, or 13 with it off.",
        LEFT + 17,
        234,
        WIDTH - 34,
        size=8.45,
        leading=11.5,
        color=MUTED,
        max_height=27,
    )

    section(c, "SCREENS / CHANGING WITH THE EVIDENCE", 289)
    panel(c, 301, 113)
    left_x, right_x = LEFT + 15, LEFT + 272
    for index, (name, detail) in enumerate(
        [
            ("MISSION", "current pass + priority signals"),
            ("NETWORK", "hosts, ports + web replies"),
            ("PROCESSES", "memory + new executions"),
            ("TRAFFIC", "interface rates + history"),
            ("PACKETS", "flows, DNS + TLS names"),
        ]
    ):
        screen_row(c, left_x, 324 + index * 19, name, detail)
    for index, (name, detail) in enumerate(
        [
            ("BINARIES", "recent executable dossiers"),
            ("DISASM", "instructions + control flow"),
            ("RUNTIME", "stacks, files + sockets"),
            ("THREAT INTEL", "provider reports + context"),
            ("SIGNALS", "high-signal event timeline"),
        ]
    ):
        screen_row(c, right_x, 324 + index * 19, name, detail)

    section(c, "CONTROL THE LIVE WORKSPACE", 437)
    panel(c, 450, 96, accent=True)
    controls = [
        ("F3", "browse/pin a screen; Up/Down scroll"),
        ("F8", "pause or resume automatic screen changes"),
        ("F7", "pause or resume live follow-ups"),
        ("F5 then n", "turn the LAN survey on or off"),
    ]
    for index, (key, description) in enumerate(controls):
        top = 472 + index * 20
        text(c, key, LEFT + 17, top, "Courier-Bold", 8.8, CYAN)
        text(c, description, LEFT + 117, top, "Helvetica", 8.75, PALE)
    text(c, "Views change about every 5 seconds. Local follow-ups run about every 20 seconds.", LEFT, 563, "Helvetica", 8.1, MUTED)

    section(c, "RUN A SPECIFIC CHECK", 587)
    panel(c, 599, 112, x=LEFT, width=256, accent=True)
    panel(c, 599, 112, x=LEFT + 272, width=256, accent=True)
    text(c, "LIVE / RUNTIME", LEFT + 14, 617, "Courier-Bold", 8.0, CYAN)
    text(c, "FILES / INTELLIGENCE", LEFT + 286, 617, "Courier-Bold", 8.0, CYAN)
    code(
        c,
        [
            "spectre capture live --seconds 5",
            "spectre runtime resources 1234",
            "spectre runtime sample 1234 --seconds 2",
            "spectre runtime trace 1234 '*getpid*'",
        ],
        LEFT + 14,
        635,
        size=7.2,
        leading=19,
        max_width=228,
    )
    code(
        c,
        [
            "spectre disassemble /bin/ls --instructions 64",
            "spectre intel status",
            "spectre intel query cisa cve CVE-2021-44228",
            "spectre intel query circl hash YOUR_SHA256",
        ],
        LEFT + 286,
        635,
        size=7.1,
        leading=19,
        max_width=228,
    )
    para(
        c,
        "Replace 1234 with a real PID and YOUR_SHA256 with your file hash. For VirusTotal or AbuseIPDB, add your own API key to ~/.zshrc using SPECTRE_VT_API_KEY or SPECTRE_ABUSEIPDB_API_KEY.",
        LEFT,
        716,
        WIDTH,
        size=7.5,
        leading=9.5,
        color=MUTED,
        max_height=21,
    )
    c.showPage()


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(OUTPUT), pagesize=(W, H), pageCompression=1)
    c.setTitle("SPECTRE | Quick Start")
    c.setAuthor("Cade Masterson")
    c.setSubject("SPECTRE overview, macOS setup, Assisted session, and research commands")
    c.setCreator("SPECTRE")
    first_page(c)
    second_page(c)
    c.save()
    copyfile(OUTPUT, PUBLIC_COPY)
    print(OUTPUT)


if __name__ == "__main__":
    main()
