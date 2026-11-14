#!/usr/bin/env python3
"""Capture a real offline SPECTRE TUI session as a PNG.

Requires pyte and Pillow. Run from the repository root after `cargo build`:
    python3 -m pip install pyte Pillow
    python3 tools/capture_offline.py

The session reads only /bin/ls. It uses an isolated temporary configuration with
all autonomous modules disabled, sends `binary /bin/ls`, and captures the PTY
screen after selecting a binary identity observation.
"""

from __future__ import annotations

import codecs
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import tempfile
import termios
import time

try:
    import pyte
    from PIL import Image, ImageDraw, ImageFont
except ImportError as exc:
    raise SystemExit("Install capture dependencies with: python3 -m pip install pyte Pillow") from exc

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "assets" / "offline-binary.png"
BINARY = ROOT / "target" / "debug" / "spectre"
COLS = 132
ROWS = 40
FONT_CANDIDATES = (
    Path("/System/Library/Fonts/Menlo.ttc"),
    Path.home() / "Library/Fonts/JetBrainsMonoNLNerdFontMono-Regular.ttf",
    Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
)
DEFAULT_FG = (207, 221, 226)
DEFAULT_BG = (9, 14, 20)
NAMED_COLORS = {
    "black": (0, 0, 0), "red": (205, 49, 49), "green": (13, 188, 121),
    "brown": (229, 229, 16), "blue": (36, 114, 200), "magenta": (188, 63, 188),
    "cyan": (17, 168, 205), "white": (229, 229, 229),
    "brightblack": (102, 102, 102), "brightred": (241, 76, 76),
    "brightgreen": (35, 209, 139), "brightyellow": (245, 245, 67),
    "brightblue": (59, 142, 234), "brightmagenta": (214, 112, 214),
    "brightcyan": (41, 184, 219), "brightwhite": (255, 255, 255),
}


def color(value: str, default: tuple[int, int, int]) -> tuple[int, int, int]:
    if value == "default":
        return default
    if re.fullmatch(r"[0-9a-fA-F]{6}", value):
        return tuple(bytes.fromhex(value))
    return NAMED_COLORS.get(value, default)


def find_font() -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if path.exists():
            return ImageFont.truetype(str(path), 18)
    raise SystemExit("A monospace font is required to render the capture")


def render_png(screen: pyte.Screen, output: Path) -> None:
    font = find_font()
    cell_w = round(font.getlength("M"))
    cell_h = 25
    margin_x, margin_y = 24, 20
    image = Image.new("RGB", (COLS * cell_w + 2 * margin_x, ROWS * cell_h + 2 * margin_y), DEFAULT_BG)
    draw = ImageDraw.Draw(image)
    for y in range(ROWS):
        for x in range(COLS):
            char = screen.buffer[y][x]
            bg = color(char.bg, DEFAULT_BG)
            fg = color(char.fg, DEFAULT_FG)
            left = margin_x + x * cell_w
            top = margin_y + y * cell_h
            draw.rectangle((left, top, left + cell_w, top + cell_h), fill=bg)
            if char.data and char.data != " ":
                draw.text((left, top), char.data, font=font, fill=fg)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output, optimize=True)


def screen_text(screen: pyte.Screen) -> str:
    return "\n".join(screen.display)


def main() -> None:
    if not BINARY.exists():
        raise SystemExit("Build SPECTRE first: cargo build")
    with tempfile.TemporaryDirectory(prefix="spectre-capture-") as temporary:
        config_path = Path(temporary) / "config.toml"
        config_path.write_text(
            'profile = "offline"\n'
            'theme = "intelligence"\n'
            'refresh_ms = 250\n'
            'retention_events = 1000\n'
            'autonomous = false\n'
            'enabled_modules = []\n'
            'allowed_targets = []\n'
            'prepared_workflow = []\n'
        )
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
        environment = os.environ.copy()
        environment["TERM"] = "xterm-256color"
        environment["COLORTERM"] = "truecolor"
        environment.pop("NO_COLOR", None)
        process = subprocess.Popen(
            [str(BINARY), "--config", str(config_path), "launch"],
            stdin=slave, stdout=slave, stderr=slave,
            cwd=ROOT, env=environment, start_new_session=True,
        )
        os.close(slave)
        screen = pyte.Screen(COLS, ROWS)
        stream = pyte.Stream(screen)
        decoder = codecs.getincrementaldecoder("utf-8")("replace")

        def pump(seconds: float) -> None:
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline and process.poll() is None:
                ready, _, _ = select.select([master], [], [], min(0.05, max(0.0, deadline - time.monotonic())))
                if ready:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    stream.feed(decoder.decode(data))

        try:
            pump(1.0)
            if "SPECTRE" not in screen_text(screen):
                raise RuntimeError("TUI did not initialize")
            os.write(master, b"binary /bin/ls\r")
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                pump(0.2)
                if "64 printable strings retained" in screen_text(screen):
                    break
            else:
                raise RuntimeError("Offline binary analysis did not appear in the TUI:\n" + screen_text(screen))
            for _ in range(90):
                if "entry_point" in screen_text(screen) and "sha256" in screen_text(screen):
                    break
                os.write(master, b"\x0b")  # Ctrl+K selects the next older observation.
                pump(0.08)
            else:
                raise RuntimeError("Could not select a binary identity observation")
            text = screen_text(screen)
            if "/bin/ls" not in text or "MachO" not in text or "sha256" not in text:
                raise RuntimeError("Captured screen lacks expected binary evidence")
            render_png(screen, OUTPUT)
            print(OUTPUT)
        finally:
            try:
                os.write(master, b"\x03")  # Ctrl+C
                pump(0.2)
            except OSError:
                pass
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            os.close(master)


if __name__ == "__main__":
    main()
