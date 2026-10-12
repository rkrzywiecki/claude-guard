"""Render docs/demo.gif from real claude-guard runs.

Each scene runs a command from the README, captures its colored output and draws it as terminal
frames, so the GIF always shows what the current code prints:

    uv run --with pillow python scripts/demo_gif.py

Pillow is only needed here, so it is not a project dependency.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent

COLUMNS = 96
ROWS = 24
PADDING = 16
FONT_SIZE = 15

SCENES = [
    (
        "# A prompt injection hidden in a fetched web page",
        "uv run claude-guard scan --file examples/prompt_injection.json",
    ),
    (
        "# A password and a card number in a prompt",
        "uv run claude-guard scan --file examples/secret.json --redacted",
    ),
    (
        "# Claude Code hook: the agent tries to run rm -rf /",
        "uv run claude-guard hook PreToolUse < examples/rm_rf_tool_input.json"
        " | python3 -m json.tool",
    ),
]

BACKGROUND = (30, 33, 40)
FOREGROUND = (220, 223, 228)
COMMENT = (128, 134, 145)
PROMPT = (97, 175, 239)
# Standard and bright ANSI colors (30-37, 90-97).
ANSI = [
    (40, 44, 52),
    (224, 108, 117),
    (152, 195, 121),
    (229, 192, 123),
    (97, 175, 239),
    (198, 120, 221),
    (86, 182, 194),
    (220, 223, 228),
]
ANSI_BRIGHT = [
    (92, 99, 112),
    (240, 135, 142),
    (175, 215, 145),
    (240, 210, 150),
    (125, 195, 250),
    (215, 150, 235),
    (115, 205, 215),
    (255, 255, 255),
]

SGR = re.compile(r"\x1b\[([0-9;]*)m")

Color = tuple[int, int, int]


@dataclass(frozen=True)
class Cell:
    char: str
    color: Color
    bold: bool


Line = list[Cell]


def xterm_256(index: int) -> Color:
    if index < 8:
        return ANSI[index]
    if index < 16:
        return ANSI_BRIGHT[index - 8]
    if index < 232:
        index -= 16
        steps = [0, 95, 135, 175, 215, 255]
        return steps[index // 36], steps[index // 6 % 6], steps[index % 6]
    level = 8 + (index - 232) * 10
    return level, level, level


def parse_ansi(text: str, color: Color = FOREGROUND) -> list[Line]:
    """Split colored output into lines of cells, wrapped at COLUMNS."""
    lines: list[Line] = [[]]
    current, bold = color, False
    position = 0
    for match in [*SGR.finditer(text), None]:
        end = match.start() if match else len(text)
        for char in text[position:end]:
            if char == "\n":
                lines.append([])
                continue
            if len(lines[-1]) == COLUMNS:
                lines.append([])
            lines[-1].append(Cell(char, current, bold))
        if match is None:
            break
        position = match.end()
        codes = [int(code) for code in match.group(1).split(";") if code] or [0]
        i = 0
        while i < len(codes):
            code = codes[i]
            if code == 0:
                current, bold = color, False
            elif code == 1:
                bold = True
            elif code == 22:
                bold = False
            elif code == 39:
                current = color
            elif 30 <= code <= 37:
                current = ANSI[code - 30]
            elif 90 <= code <= 97:
                current = ANSI_BRIGHT[code - 90]
            elif code == 38 and codes[i + 1 : i + 2] == [5]:
                current = xterm_256(codes[i + 2])
                i += 2
            elif code == 38 and codes[i + 1 : i + 2] == [2]:
                current = (codes[i + 2], codes[i + 3], codes[i + 4])
                i += 4
            i += 1
    if not lines[-1]:
        lines.pop()
    return lines


def plain(text: str, color: Color, bold: bool = False) -> Line:
    return [Cell(char, color, bold) for char in text]


def run(command: str) -> str:
    env = {**os.environ, "FORCE_COLOR": "1", "COLUMNS": str(COLUMNS), "TERM": "xterm-256color"}
    result = subprocess.run(  # noqa: S602 - fixed commands from SCENES
        command, shell=True, cwd=ROOT, env=env, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        sys.exit(f"{command!r} failed ({result.returncode}):\n{result.stderr}")
    return result.stdout


class Renderer:
    def __init__(self, font_path: str) -> None:
        self.regular = ImageFont.truetype(font_path, FONT_SIZE, index=0)
        try:
            self.bold = ImageFont.truetype(font_path, FONT_SIZE, index=1)
        except OSError:
            self.bold = self.regular
        _, top, _, bottom = self.regular.getbbox("M")
        self.cell_width = round(self.regular.getlength("M"))
        self.cell_height = round((bottom - top) * 1.6)
        self.size = (
            COLUMNS * self.cell_width + 2 * PADDING,
            ROWS * self.cell_height + 2 * PADDING,
        )

    def draw(self, lines: list[Line], cursor: bool) -> Image.Image:
        image = Image.new("RGB", self.size, BACKGROUND)
        draw = ImageDraw.Draw(image)
        visible = lines[-ROWS:]
        for row, line in enumerate(visible):
            y = PADDING + row * self.cell_height
            for column, cell in enumerate(line):
                if cell.char != " ":
                    x = PADDING + column * self.cell_width
                    font = self.bold if cell.bold else self.regular
                    draw.text((x, y), cell.char, font=font, fill=cell.color)
        if cursor and visible:
            x = PADDING + len(visible[-1]) * self.cell_width
            y = PADDING + (len(visible) - 1) * self.cell_height
            draw.rectangle(
                (x, y + 2, x + self.cell_width - 2, y + self.cell_height - 4), fill=FOREGROUND
            )
        return image


def build_frames(renderer: Renderer) -> tuple[list[Image.Image], list[int]]:
    frames: list[Image.Image] = []
    durations: list[int] = []

    def add(lines: list[Line], duration: int, cursor: bool = True) -> None:
        frames.append(renderer.draw(lines, cursor))
        durations.append(duration)

    for comment, command in SCENES:
        lines: list[Line] = [plain(comment, COMMENT), plain("$ ", PROMPT)]
        add(lines, 600)
        for start in range(0, len(command), 3):
            lines[-1] = plain("$ ", PROMPT) + plain(command[: start + 3], FOREGROUND, bold=True)
            add(lines, 45)
        add(lines, 500)
        lines = [*lines, *parse_ansi(run(command))]
        add(lines, 4500, cursor=False)
    return frames, durations


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--font", default="/System/Library/Fonts/Menlo.ttc")
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "demo.gif")
    args = parser.parse_args()

    frames, durations = build_frames(Renderer(args.font))
    frames[0].save(
        args.output,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"{args.output.relative_to(ROOT)}: {len(frames)} frames")


if __name__ == "__main__":
    main()
