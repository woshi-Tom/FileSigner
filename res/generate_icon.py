"""Generate a 32x32 RGBA icon for FileSigner."""
import struct
import os

W, H = 32, 32

# Create a 32x32 RGBA pixel array
pixels = []
for y in range(H):
    row = []
    for x in range(W):
        # Simple design: blue shield/badge with white "S"
        cx, cy = 16, 16  # center
        dx, dy = x - cx + 0.5, y - cy + 0.5
        dist = (dx*dx + dy*dy) ** 0.5

        if dist < 13:
            # Inner circle: white
            if dist < 9:
                r, g, b, a = 255, 255, 255, 255
            else:
                # Outer ring: blue
                r, g, b, a = 37, 99, 235, 255
        else:
            r, g, b, a = 0, 0, 0, 0

        # Draw a simple pen/nib shape using pixel art
        if 5 <= x <= 26 and 12 <= y <= 20:
            if y == 12 or y == 20:
                if 7 <= x <= 15 and y == 12:
                    r, g, b = 37, 99, 235
                elif x == 15 and 14 <= y <= 18:
                    r, g, b = 37, 99, 235
                elif x == 17 and 14 <= y <= 18:
                    r, g, b = 37, 99, 235

        row.append((r, g, b, a))
    pixels.append(row)

# Build BMP + AND mask
# BITMAPINFOHEADER
bmp_size = 40 + H * W * 4 + H * (W // 8)  # header + pixels + mask
bmp_data = bytearray()
bmp_data += struct.pack('<IiiHHIIiiII',
                         40,        # biSize
                         W,         # biWidth
                         H * 2,     # biHeight (includes AND mask)
                         1,         # biPlanes
                         32,        # biBitCount
                         0,         # biCompression
                         W * H * 4, # biSizeImage
                         0, 0, 0, 0)

# Pixel data (bottom-up)
for row in reversed(pixels):
    for r, g, b, a in row:
        bmp_data += struct.pack('BBBB', b, g, r, a)

# AND mask (all zeros = fully opaque where alpha > 0)
for y in range(H):
    mask_row = 0
    for x in range(W):
        if pixels[y][x][3] > 0:
            mask_row |= (1 << (7 - (x % 8)))
    for byte_idx in range(W // 8):
        bmp_data.append((mask_row >> (8 * ((W // 8) - 1 - byte_idx))) & 0xFF)

# ICO header
ico = bytearray()
ico += struct.pack('<HHH', 0, 1, 1)   # reserved, type=icon, 1 image

# ICO directory entry
ico += struct.pack('<BBBBHHII',
                    W, H,            # width, height (0 = 256 for 0..255)
                    0,               # color count
                    0,               # reserved
                    1,               # planes
                    32,              # bpp
                    len(bmp_data),   # size
                    22)              # offset

ico += bmp_data

output = os.path.join('res', 'app.ico')
os.makedirs('res', exist_ok=True)
with open(output, 'wb') as f:
    f.write(ico)
print(f'Created {output} ({len(ico)} bytes)')
