"""Read the completion signature from cp-uarm's RGB/RGBA PNG screenshots.

Uses only the Python standard library. No OCR or Palm OS calls are needed.
"""
import struct
import zlib


def status(path):
    png = path.read_bytes()
    if png[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('invalid screenshot PNG')
    offset, compressed = 8, bytearray()
    width = height = channels = 0
    while offset < len(png):
        size = struct.unpack_from('>I', png, offset)[0]
        kind = png[offset + 4:offset + 8]
        data = png[offset + 8:offset + 8 + size]
        offset += size + 12
        if kind == b'IHDR':
            width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', data)
            if depth != 8 or color not in (2, 6) or compression or filtering or interlace:
                raise ValueError('expected a non-interlaced 8-bit RGB/RGBA screenshot')
            channels = 3 if color == 2 else 4
        elif kind == b'IDAT':
            compressed.extend(data)
    raw = zlib.decompress(compressed)
    stride = width * channels
    if len(raw) != height * (stride + 1):
        raise ValueError('invalid screenshot data length')
    rows = []
    previous = bytearray(stride)
    for y in range(height):
        start = y * (stride + 1)
        filtering = raw[start]
        row = bytearray(raw[start + 1:start + 1 + stride])
        if filtering not in range(5):
            raise ValueError('invalid PNG filter')
        for x in range(stride):
            left = row[x - channels] if x >= channels else 0
            above = previous[x]
            upper_left = previous[x - channels] if x >= channels else 0
            if filtering == 1:
                predictor = left
            elif filtering == 2:
                predictor = above
            elif filtering == 3:
                predictor = (left + above) // 2
            elif filtering == 4:
                p = left + above - upper_left
                distances = [abs(p - left), abs(p - above), abs(p - upper_left)]
                predictor = [left, above, upper_left][distances.index(min(distances))]
            else:
                predictor = 0
            row[x] = (row[x] + predictor) & 255
        rows.append(row)
        previous = row
    # Palm's 160-unit coordinate system is scaled by the display density.
    if width % 160:
        raise ValueError('unsupported screenshot width')
    scale = width // 160
    if scale == 0 or height <= 140 * scale:
        raise ValueError('screenshot is too small')
    observed = []
    for y in range(4):
        bits = 0
        for x in range(8):
            px = (144 + x) * scale + scale // 2
            py = (136 + y) * scale + scale // 2
            value = rows[py][px * channels:px * channels + 3]
            bits = (bits << 1) | (sum(value) < 384)
        observed.append(bits)
    pattern = [0xa5, 0x3c, 0xc3, 0x5a]
    if observed == pattern:
        return True
    if observed == [x ^ 255 for x in pattern]:
        return False
    return None
