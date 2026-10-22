"""Generate the app icons and glyphs: a bold "Q" mark.

Run with Pillow installed, from the repository root:

    python3 tools/make_icons.py

Formats follow Ledger's icon checks (ledger-app-workflows check_icons.sh): no
alpha channel; Nano and Apex P icons bilevel black and white with a 1-bit
depth; Stax and Flex at most 16 grey levels. Nano icons are white on black,
touch-screen icons black on white.
"""

from pathlib import Path

from PIL import Image, ImageDraw

APP = Path(__file__).resolve().parent.parent / "app"

# Hand-drawn 14x14 mark for Nano, where scaling artefacts show.
NANO_Q = [
    "..............",
    "....######....",
    "...########...",
    "..###....###..",
    "..##......##..",
    "..##......##..",
    "..##......##..",
    "..##..##..##..",
    "..###..####...",
    "...########...",
    "....#######...",
    "..........###.",
    "...........#..",
    "..............",
]

# Rounded square the Nano home glyph is cut from (see build.rs).
NANO_MASK = [
    "...########...",
    ".############.",
    ".############.",
    "##############",
    "##############",
    "##############",
    "##############",
    "##############",
    "##############",
    "##############",
    "##############",
    ".############.",
    ".############.",
    "...########...",
]


def bitmap(rows, on=255, off=0):
    img = Image.new("L", (len(rows[0]), len(rows)), off)
    for y, row in enumerate(rows):
        for x, c in enumerate(row):
            if c == "#":
                img.putpixel((x, y), on)
    return img


def q_mark(size, levels):
    """Black "Q" on white, drawn at 8x and reduced to `levels` grey levels (2 = 1-bit)."""
    s = size * 8
    img = Image.new("L", (s, s), 255)
    d = ImageDraw.Draw(img)
    stroke = round(s * 0.13)
    margin = round(s * 0.12)
    d.ellipse([margin, margin, s - margin, s - margin - round(s * 0.04)], outline=0, width=stroke)
    d.line([(s * 0.57, s * 0.58), (s * 0.88, s * 0.90)], fill=0, width=stroke)
    img = img.resize((size, size), Image.LANCZOS)
    step = 255 / (levels - 1)
    return img.point(lambda v: int(round(round(v / step) * step)))


def bilevel(img):
    """A 2-entry palette image (black, white): what Ledger's check reads as Bilevel, 1-bit."""
    out = Image.new("P", img.size, 0)
    out.putpalette([0, 0, 0, 255, 255, 255])
    out.putdata([1 if v >= 128 else 0 for v in img.getdata()])
    return out


def save(img, path, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode == "1":
        bilevel(img).save(path, bits=1)
    else:
        img.convert("L").save(path, optimize=False)


def main():
    save(bitmap(NANO_Q), APP / "icons/qsb_14x14.gif", "1")
    save(bitmap(NANO_MASK), APP / "icons/mask_14x14.gif", "1")
    save(q_mark(32, 16), APP / "icons/qsb_32x32.gif", "L")
    save(q_mark(40, 16), APP / "icons/qsb_40x40.gif", "L")
    save(q_mark(32, 2), APP / "icons/qsb_32x32.png", "1")
    save(q_mark(64, 16), APP / "glyphs/qsb_64x64.gif", "L")
    save(q_mark(48, 2), APP / "glyphs/qsb_48x48.png", "1")


if __name__ == "__main__":
    main()
