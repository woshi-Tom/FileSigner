"""Generate a multi-resolution ICO icon for FileSigner.
Shield + checkmark design with blue gradient, no external dependencies."""
import struct
import math
import os

def draw_gradient_rect(pixels, w, h, x0, y0, rw, rh, c1, c2, vertical=True):
    """Fill a rectangle with a linear gradient from c1 to c2."""
    for dy in range(rh):
        for dx in range(rw):
            px, py = x0 + dx, y0 + dy
            if 0 <= px < w and 0 <= py < h:
                t = (dy / max(rh - 1, 1)) if vertical else (dx / max(rw - 1, 1))
                r = int(c1[0] + (c2[0] - c1[0]) * t)
                g = int(c1[1] + (c2[1] - c1[1]) * t)
                b = int(c1[2] + (c2[2] - c1[2]) * t)
                pixels[py][px] = (r, g, b, 255)

def draw_filled_circle(pixels, w, h, cx, cy, radius, color, alpha=255):
    """Draw a filled circle with anti-aliasing at edges."""
    for y in range(max(0, int(cy - radius - 1)), min(h, int(cy + radius + 2))):
        for x in range(max(0, int(cx - radius - 1)), min(w, int(cx + radius + 2))):
            dx, dy = x - cx, y - cy
            dist = math.sqrt(dx * dx + dy * dy)
            if dist <= radius - 0.5:
                r, g, b = color
                pixels[y][x] = (r, g, b, alpha)
            elif dist <= radius + 0.5:
                # Anti-alias edge
                aa = max(0, min(255, int(alpha * (radius + 0.5 - dist))))
                or_, og, ob, oa = pixels[y][x]
                r = int(color[0] * aa / 255 + or_ * (255 - aa) / 255)
                g = int(color[1] * aa / 255 + og * (255 - aa) / 255)
                b = int(color[2] * aa / 255 + ob * (255 - aa) / 255)
                a = min(255, oa + aa)
                pixels[y][x] = (r, g, b, a)

def draw_rounded_rect(pixels, w, h, x0, y0, rw, rh, radius, color, alpha=255):
    """Draw a filled rounded rectangle."""
    for y in range(max(0, y0), min(h, y0 + rh)):
        for x in range(max(0, x0), min(w, x0 + rw)):
            # Check if point is inside rounded rect
            inside = True
            # Top-left corner
            if x < x0 + radius and y < y0 + radius:
                if math.sqrt((x - x0 - radius)**2 + (y - y0 - radius)**2) > radius:
                    inside = False
            # Top-right corner
            if x >= x0 + rw - radius and y < y0 + radius:
                if math.sqrt((x - x0 - rw + radius)**2 + (y - y0 - radius)**2) > radius:
                    inside = False
            # Bottom-left corner
            if x < x0 + radius and y >= y0 + rh - radius:
                if math.sqrt((x - x0 - radius)**2 + (y - y0 - rh + radius)**2) > radius:
                    inside = False
            # Bottom-right corner
            if x >= x0 + rw - radius and y >= y0 + rh - radius:
                if math.sqrt((x - x0 - rw + radius)**2 + (y - y0 - rh + radius)**2) > radius:
                    inside = False

            if inside:
                r, g, b = color
                # Simple alpha blend
                or_, og, ob, oa = pixels[y][x]
                nr = int(r * alpha / 255 + or_ * (255 - alpha) / 255)
                ng = int(g * alpha / 255 + og * (255 - alpha) / 255)
                nb = int(b * alpha / 255 + ob * (255 - alpha) / 255)
                pixels[y][x] = (nr, ng, nb, min(255, oa + alpha))

def draw_shield(pixels, w, h, cx, cy, size):
    """Draw a shield shape with gradient fill and checkmark."""
    # Shield path - simplified polygon
    shield_pts = []
    for angle_deg in range(0, 360, 1):
        angle = math.radians(angle_deg)
        # Shield shape: rounded top, pointed bottom
        if angle_deg < 180:  # top half
            rx = size * 0.45 * math.cos(angle)
            ry = size * 0.4 * math.sin(angle) * 0.7
        else:  # bottom half - taper to point
            t = (angle_deg - 180) / 180.0
            taper = 1.0 - t * 0.85
            rx = size * 0.45 * math.cos(angle) * taper
            ry = size * 0.4 * math.sin(angle) * 0.7 + size * 0.05 * t
        shield_pts.append((cx + rx, cy + ry - size * 0.05))

    # Draw shield with gradient
    # Fill shield area
    for y in range(max(0, int(cy - size * 0.45)), min(h, int(cy + size * 0.45))):
        for x in range(max(0, int(cx - size * 0.45)), min(w, int(cx + size * 0.45))):
            # Check if point is inside shield using ray casting
            px, py = x - cx, y - (cy - size * 0.05)
            # Normalize
            nx = px / (size * 0.45)
            ny_top = py / (size * 0.35)
            ny_bot = py / (size * 0.45)

            if py < 0:  # top half
                if nx * nx + ny_top * ny_top < 0.92:
                    # Gradient: lighter at top, darker at bottom
                    t = (y - (cy - size * 0.4)) / (size * 0.8)
                    t = max(0, min(1, t))
                    r = int(140 + (80 - 140) * t)
                    g = int(170 + (120 - 170) * t)
                    b = int(220 + (190 - 220) * t)
                    pixels[y][x] = (r, g, b, 255)
            else:  # bottom half - taper
                taper = max(0.1, 1.0 - (py / (size * 0.45)) * 0.7)
                adj_nx = nx / taper if taper > 0.01 else 999
                if adj_nx * adj_nx + ny_bot * ny_bot < 0.92:
                    t = (y - (cy - size * 0.4)) / (size * 0.8)
                    t = max(0, min(1, t))
                    r = int(140 + (80 - 140) * t)
                    g = int(170 + (120 - 170) * t)
                    b = int(220 + (190 - 220) * t)
                    pixels[y][x] = (r, g, b, 255)

    # Draw shield border
    for angle_deg in range(0, 360, 1):
        angle = math.radians(angle_deg)
        if angle_deg < 180:
            rx = size * 0.45 * math.cos(angle)
            ry = size * 0.4 * math.sin(angle) * 0.7
        else:
            t = (angle_deg - 180) / 180.0
            taper = 1.0 - t * 0.85
            rx = size * 0.45 * math.cos(angle) * taper
            ry = size * 0.4 * math.sin(angle) * 0.7 + size * 0.05 * t
        bx = int(cx + rx)
        by = int(cy + ry - size * 0.05)
        for d in range(-1, 2):
            for e in range(-1, 2):
                if 0 <= bx + d < w and 0 <= by + e < h:
                    pixels[by + e][bx + d] = (60, 72, 180, 255)

    # Draw checkmark
    cm_size = size * 0.35
    # Checkmark points relative to center
    p1 = (cx - cm_size * 0.4, cy + size * 0.02)  # left
    p2 = (cx - cm_size * 0.05, cy + cm_size * 0.35 + size * 0.02)  # middle
    p3 = (cx + cm_size * 0.45, cy - cm_size * 0.35 + size * 0.02)  # right

    # Draw thick checkmark lines
    line_width = max(2, int(size * 0.07))
    for t in range(100):
        ft = t / 100.0
        # First segment: p1 to p2
        x = int(p1[0] + (p2[0] - p1[0]) * ft)
        y = int(p1[1] + (p2[1] - p1[1]) * ft)
        for dy in range(-line_width, line_width + 1):
            for dx in range(-line_width, line_width + 1):
                if dx * dx + dy * dy <= line_width * line_width:
                    px, py = x + dx, y + dy
                    if 0 <= px < w and 0 <= py < h:
                        pixels[py][px] = (255, 255, 255, 255)

    for t in range(100):
        ft = t / 100.0
        # Second segment: p2 to p3
        x = int(p2[0] + (p3[0] - p2[0]) * ft)
        y = int(p2[1] + (p3[1] - p2[1]) * ft)
        for dy in range(-line_width, line_width + 1):
            for dx in range(-line_width, line_width + 1):
                if dx * dx + dy * dy <= line_width * line_width:
                    px, py = x + dx, y + dy
                    if 0 <= px < w and 0 <= py < h:
                        pixels[py][px] = (255, 255, 255, 255)

    # Add subtle inner highlight (top-left glow)
    draw_filled_circle(pixels, w, h, cx - size * 0.15, cy - size * 0.2,
                       size * 0.12, (160, 190, 255), 80)

def generate_icon(size):
    """Generate icon pixels at given size."""
    pixels = [[(0, 0, 0, 0)] * size for _ in range(size)]

    # Draw shadow
    draw_filled_circle(pixels, size, size,
                       size * 0.52, size * 0.55,
                       size * 0.4, (0, 0, 0), 40)

    # Draw shield with checkmark
    draw_shield(pixels, size, size, size * 0.5, size * 0.48, size * 0.85)

    return pixels

def build_ico(sizes_and_pixels):
    """Build an ICO file from multiple pixel arrays."""
    images = []

    for size, pixels in sizes_and_pixels:
        w = h = size

        # Build BMP data (BITMAPINFOHEADER + pixel data + AND mask)
        bmp = bytearray()

        # BITMAPINFOHEADER
        row_size = w * 4
        and_row_size = ((w + 31) // 32) * 4  # DWORD-aligned
        bmp += struct.pack('<IiiHHIIiiII',
                           40,               # biSize
                           w,                # biWidth
                           h * 2,            # biHeight (doubled for ICO)
                           1,                # biPlanes
                           32,               # biBitCount (ARGB)
                           0,                # biCompression
                           row_size * h,     # biSizeImage
                           0, 0,             # biXPelsPerMeter, biYPelsPerMeter
                           0, 0)             # biClrUsed, biClrImportant

        # Pixel data (bottom-up, BGRA)
        for row in reversed(pixels):
            for r, g, b, a in row:
                bmp += struct.pack('BBBB', b, g, r, a)

        # AND mask (1bpp, all zeros = opaque)
        for _ in range(h):
            bmp += b'\x00' * and_row_size

        images.append((w, h, bmp))

    # Build ICO file
    ico = bytearray()
    # ICO header
    ico += struct.pack('<HHH', 0, 1, len(images))  # reserved, type=icon, count

    # Calculate offsets
    dir_size = 6 + 16 * len(images)
    offset = dir_size

    # Directory entries + image data
    image_data = bytearray()
    for w, h, bmp in images:
        # Directory entry
        ico += struct.pack('<BBBBHHII',
                           w if w < 256 else 0,   # width (0 = 256)
                           h if h < 256 else 0,   # height (0 = 256)
                           0,                      # color count
                           0,                      # reserved
                           1,                      # planes
                           32,                     # bpp
                           len(bmp),               # size
                           offset)                 # offset
        image_data += bmp
        offset += len(bmp)

    ico += image_data
    return ico

# Generate icons at multiple resolutions
print("Generating icons...")
sizes = [16, 32, 48, 256]
icons = []
for sz in sizes:
    print(f"  {sz}x{sz}...")
    icons.append((sz, generate_icon(sz)))

ico_data = build_ico(icons)
output = os.path.join('res', 'app.ico')
os.makedirs('res', exist_ok=True)
with open(output, 'wb') as f:
    f.write(ico_data)
print(f"Created {output} ({len(ico_data)} bytes, {len(sizes)} resolutions)")
