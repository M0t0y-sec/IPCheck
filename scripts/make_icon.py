"""Generate the IPCheck app icon.

Design: a shield outline (the "check/verify" idea) containing three ascending
signal bars, over a deep teal-to-indigo gradient. Rendered at 1024px and let
Tauri's icon tool downscale, so every size in the bundle comes from one source.

Run:  python scripts/make_icon.py
"""

from PIL import Image, ImageDraw
import math
import os

SIZE = 1024
BG_TOP = (13, 148, 136)      # teal-600
BG_BOTTOM = (67, 56, 202)    # indigo-700
FG = (255, 255, 255)


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def gradient(size):
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        t = y / (size - 1)
        c = lerp(BG_TOP, BG_BOTTOM, t)
        for x in range(size):
            px[x, y] = c
    return img


def shield_path(cx, cy, w, h):
    """A shield outline: flat-ish shoulders, tapering to a rounded point."""
    top = cy - h / 2
    bottom = cy + h / 2
    left = cx - w / 2
    right = cx + w / 2
    shoulder = top + h * 0.42

    pts = []
    # Top-left shoulder
    pts.append((left, top + h * 0.10))
    pts.append((cx, top))
    # Top-right shoulder
    pts.append((right, top + h * 0.10))
    # Right edge down to the shoulder line
    pts.append((right, shoulder))
    # Taper to the bottom point with a slight curve
    steps = 24
    for i in range(1, steps + 1):
        t = i / steps
        # quadratic ease so the sides curve inward like a real shield
        x = right + (cx - right) * (t ** 1.7)
        y = shoulder + (bottom - shoulder) * t
        pts.append((x, y))
    for i in range(steps - 1, -1, -1):
        t = i / steps
        x = left + (cx - left) * (t ** 1.7)
        y = shoulder + (bottom - shoulder) * t
        pts.append((x, y))
    # Left edge back up
    pts.append((left, shoulder))
    return pts


def rounded_rect(draw, box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def main():
    img = gradient(SIZE).convert("RGBA")
    overlay = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)

    cx, cy = SIZE / 2, SIZE / 2 + 8
    w, h = SIZE * 0.62, SIZE * 0.72

    pts = shield_path(cx, cy, w, h)

    # Shield filled with a translucent white so the gradient reads through it.
    d.polygon(pts, fill=(255, 255, 255, 34))
    d.line(pts + [pts[0]], fill=FG + (235,), width=int(SIZE * 0.022),
           joint="curve")

    # Three signal bars inside the shield, ascending.
    bar_w = SIZE * 0.072
    gap = SIZE * 0.045
    total = bar_w * 3 + gap * 2
    x0 = cx - total / 2
    base_y = cy + h * 0.20
    heights = [h * 0.20, h * 0.30, h * 0.40]

    for i, bh in enumerate(heights):
        x = x0 + i * (bar_w + gap)
        box = [x, base_y - bh, x + bar_w, base_y]
        rounded_rect(d, box, radius=int(bar_w * 0.42), fill=FG + (255,))

    img = Image.alpha_composite(img, overlay)

    # Round the whole thing so it sits well as a tray/desktop icon.
    mask = Image.new("L", (SIZE, SIZE), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, SIZE - 1, SIZE - 1], radius=int(SIZE * 0.22), fill=255
    )
    out = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)
    target = os.path.join(root, "src-tauri", "icons")
    os.makedirs(target, exist_ok=True)
    src = os.path.join(target, "source.png")
    out.save(src)
    print(f"wrote {src}")


if __name__ == "__main__":
    main()
