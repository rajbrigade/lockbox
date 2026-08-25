"""A small, dependency-free QR encoder (byte mode, versions 1-10, EC level L/M).

Written from the ISO/IEC 18004 specification so that TOTP enrolment QR codes can
be produced on a machine with no network and no imaging libraries. QR is an
error-correcting code, not a cryptographic primitive, so implementing it here
does not violate the "never roll your own crypto" rule -- the *secret* inside
the QR still comes from the audited CSPRNG.

Correctness is pinned by tests that compare the generated module matrix against
the reference `qrcode` package (a development-only dependency; it is not
imported at runtime and not required to install or run Lockbox).

Not implemented: reading QR codes. That needs a camera or an image decoder,
i.e. a large binary dependency, so Lockbox does not claim it. Paste the
`otpauth://` URI or the base32 secret instead -- `tools.otp.parse_otpauth`
handles both.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

# (ec_codewords_per_block, [(block_count, data_codewords_per_block), ...])
_BLOCKS = {
    ("L", 1): (7, [(1, 19)]),
    ("M", 1): (10, [(1, 16)]),
    ("L", 2): (10, [(1, 34)]),
    ("M", 2): (16, [(1, 28)]),
    ("L", 3): (15, [(1, 55)]),
    ("M", 3): (26, [(1, 44)]),
    ("L", 4): (20, [(1, 80)]),
    ("M", 4): (18, [(2, 32)]),
    ("L", 5): (26, [(1, 108)]),
    ("M", 5): (24, [(2, 43)]),
    ("L", 6): (18, [(2, 68)]),
    ("M", 6): (16, [(4, 27)]),
    ("L", 7): (20, [(2, 78)]),
    ("M", 7): (18, [(4, 31)]),
    ("L", 8): (24, [(2, 97)]),
    ("M", 8): (22, [(2, 38), (2, 39)]),
    ("L", 9): (30, [(2, 116)]),
    ("M", 9): (22, [(3, 36), (2, 37)]),
    ("L", 10): (18, [(2, 68), (2, 69)]),
    ("M", 10): (26, [(4, 43), (1, 44)]),
}

_ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}

_EC_BITS = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}

# ---------------------------------------------------------------- GF(256) --
_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _rs_generator(n: int) -> List[int]:
    poly = [1]
    for i in range(n):
        poly.append(0)
        for j in range(len(poly) - 1, 0, -1):
            poly[j] = poly[j - 1] ^ _gf_mul(poly[j], _EXP[i])
        poly[0] = _gf_mul(poly[0], _EXP[i])
    return poly[::-1]  # descending powers, leading coefficient first


def _rs_encode(data: Sequence[int], ec_len: int) -> List[int]:
    gen = _rs_generator(ec_len)
    remainder = [0] * ec_len
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        for i in range(ec_len):
            remainder[i] ^= _gf_mul(gen[i + 1], factor)
    return remainder


# ------------------------------------------------------------- bitstream --
class _Bits:
    def __init__(self) -> None:
        self.bits: List[int] = []

    def put(self, value: int, length: int) -> None:
        for i in range(length - 1, -1, -1):
            self.bits.append((value >> i) & 1)

    def __len__(self) -> int:
        return len(self.bits)


def _capacity_bits(version: int, ec: str) -> int:
    _, groups = _BLOCKS[(ec, version)]
    return sum(count * size for count, size in groups) * 8


def _choose_version(data_len: int, ec: str, min_version: int = 1) -> int:
    for version in range(max(1, min_version), 11):
        count_bits = 8 if version <= 9 else 16
        needed = 4 + count_bits + data_len * 8
        if needed <= _capacity_bits(version, ec):
            return version
    raise ValueError(
        "data too large for this encoder (max ~230 bytes at EC level L, version 10)"
    )


def _encode_data(data: bytes, version: int, ec: str) -> List[int]:
    capacity = _capacity_bits(version, ec)
    bits = _Bits()
    bits.put(0b0100, 4)  # byte mode
    bits.put(len(data), 8 if version <= 9 else 16)
    for byte in data:
        bits.put(byte, 8)
    bits.put(0, min(4, capacity - len(bits)))
    while len(bits) % 8:
        bits.bits.append(0)
    codewords = [
        int("".join(str(b) for b in bits.bits[i : i + 8]), 2)
        for i in range(0, len(bits), 8)
    ]
    pad = [0xEC, 0x11]
    i = 0
    while len(codewords) * 8 < capacity:
        codewords.append(pad[i % 2])
        i += 1
    return codewords


def _interleave(codewords: List[int], version: int, ec: str) -> List[int]:
    ec_len, groups = _BLOCKS[(ec, version)]
    blocks: List[List[int]] = []
    ec_blocks: List[List[int]] = []
    pos = 0
    for count, size in groups:
        for _ in range(count):
            chunk = codewords[pos : pos + size]
            pos += size
            blocks.append(chunk)
            ec_blocks.append(_rs_encode(chunk, ec_len))
    out: List[int] = []
    for i in range(max(len(b) for b in blocks)):
        for block in blocks:
            if i < len(block):
                out.append(block[i])
    for i in range(ec_len):
        for block in ec_blocks:
            out.append(block[i])
    return out


# ---------------------------------------------------------------- matrix --
def _bch_format(value: int) -> int:
    data = value << 10
    for i in range(4, -1, -1):
        if data & (1 << (i + 10)):
            data ^= 0x537 << i
    return ((value << 10) | data) ^ 0x5412


def _bch_version(version: int) -> int:
    data = version << 12
    for i in range(5, -1, -1):
        if data & (1 << (i + 12)):
            data ^= 0x1F25 << i
    return (version << 12) | data


def _mask(mask_id: int, row: int, col: int) -> bool:
    if mask_id == 0:
        return (row + col) % 2 == 0
    if mask_id == 1:
        return row % 2 == 0
    if mask_id == 2:
        return col % 3 == 0
    if mask_id == 3:
        return (row + col) % 3 == 0
    if mask_id == 4:
        return (row // 2 + col // 3) % 2 == 0
    if mask_id == 5:
        return (row * col) % 2 + (row * col) % 3 == 0
    if mask_id == 6:
        return ((row * col) % 2 + (row * col) % 3) % 2 == 0
    return ((row + col) % 2 + (row * col) % 3) % 2 == 0


def _blank(size: int) -> Tuple[List[List[int]], List[List[bool]]]:
    return [[0] * size for _ in range(size)], [[False] * size for _ in range(size)]


def _place_function_patterns(m, reserved, version: int) -> None:
    size = len(m)

    def finder(r0: int, c0: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                rr, cc = r0 + r, c0 + c
                if 0 <= rr < size and 0 <= cc < size:
                    inside = 0 <= r <= 6 and 0 <= c <= 6
                    dark = inside and (
                        r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4)
                    )
                    m[rr][cc] = 1 if dark else 0
                    reserved[rr][cc] = True

    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)

    for i in range(8, size - 8):
        bit = 1 if i % 2 == 0 else 0
        m[6][i] = bit
        reserved[6][i] = True
        m[i][6] = bit
        reserved[i][6] = True

    centers = _ALIGN[version]
    last = size - 7
    for r in centers:
        for c in centers:
            # Skip only the three centres that would sit on a finder pattern.
            # Centres on the timing line are legitimate and must be drawn.
            if (r, c) in ((6, 6), (6, last), (last, 6)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    m[r + dr][c + dc] = 1 if max(abs(dr), abs(dc)) != 1 else 0
                    reserved[r + dr][c + dc] = True

    m[size - 8][8] = 1  # dark module
    reserved[size - 8][8] = True
    for i in range(9):
        if not reserved[8][i]:
            reserved[8][i] = True
        if not reserved[i][8]:
            reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True

    if version >= 7:
        for i in range(18):
            reserved[i // 3][size - 11 + i % 3] = True
            reserved[size - 11 + i % 3][i // 3] = True


def _place_data(m, reserved, bits: List[int]) -> None:
    size = len(m)
    idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if not reserved[row][c]:
                    m[row][c] = bits[idx] if idx < len(bits) else 0
                    idx += 1
        upward = not upward
        col -= 2


def _apply_format(m, ec: str, mask_id: int) -> None:
    size = len(m)
    fmt = _bch_format((_EC_BITS[ec] << 3) | mask_id)
    for i in range(15):
        bit = (fmt >> i) & 1
        if i < 6:
            m[i][8] = bit
        elif i == 6:
            m[7][8] = bit
        elif i == 7:
            m[8][8] = bit
        elif i == 8:
            m[8][7] = bit
        else:
            m[8][14 - i] = bit
        if i < 8:
            m[8][size - 1 - i] = bit
        else:
            m[size - 15 + i][8] = bit


def _apply_version(m, version: int) -> None:
    if version < 7:
        return
    size = len(m)
    info = _bch_version(version)
    for i in range(18):
        bit = (info >> i) & 1
        m[i // 3][size - 11 + i % 3] = bit
        m[size - 11 + i % 3][i // 3] = bit


def _penalty(m) -> int:
    size = len(m)
    score = 0
    for line in list(m) + [list(col) for col in zip(*m)]:
        run, prev = 1, line[0]
        for value in line[1:]:
            if value == prev:
                run += 1
            else:
                if run >= 5:
                    score += 3 + (run - 5)
                run, prev = 1, value
        if run >= 5:
            score += 3 + (run - 5)
        for i in range(size - 10):
            window = line[i : i + 11]
            if window[:7] == [1, 0, 1, 1, 1, 0, 1] and window[7:] == [0, 0, 0, 0]:
                score += 40
            if window[4:] == [1, 0, 1, 1, 1, 0, 1] and window[:4] == [0, 0, 0, 0]:
                score += 40
    for r in range(size - 1):
        for c in range(size - 1):
            block = m[r][c] + m[r][c + 1] + m[r + 1][c] + m[r + 1][c + 1]
            if block in (0, 4):
                score += 3
    dark = sum(sum(row) for row in m)
    ratio = dark * 100 // (size * size)
    score += 10 * (min(abs(ratio - 50) // 5, 10))
    return score


def encode(data: str | bytes, ec: str = "M", min_version: int = 1) -> List[List[int]]:
    """Return the QR module matrix (1 = dark) for `data`."""
    if ec not in ("L", "M"):
        raise ValueError("this encoder supports EC levels L and M")
    payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    version = _choose_version(len(payload), ec, min_version)
    codewords = _interleave(_encode_data(payload, version, ec), version, ec)
    bits = [(cw >> i) & 1 for cw in codewords for i in range(7, -1, -1)]

    size = version * 4 + 17
    best = None
    for mask_id in range(8):
        m, reserved = _blank(size)
        _place_function_patterns(m, reserved, version)
        _place_data(m, reserved, bits)
        for r in range(size):
            for c in range(size):
                if not reserved[r][c] and _mask(mask_id, r, c):
                    m[r][c] ^= 1
        _apply_format(m, ec, mask_id)
        _apply_version(m, version)
        score = _penalty(m)
        if best is None or score < best[0]:
            best = (score, m)
    assert best is not None
    return best[1]


def to_text(matrix: List[List[int]], quiet: int = 2, blocks: bool = True) -> str:
    """Render as text. Uses half-block characters so it stays square in a
    terminal; `blocks=False` falls back to ASCII for dumb consoles."""
    size = len(matrix)
    padded = [[0] * (size + quiet * 2) for _ in range(quiet)]
    for row in matrix:
        padded.append([0] * quiet + list(row) + [0] * quiet)
    padded += [[0] * (size + quiet * 2) for _ in range(quiet)]
    if not blocks:
        return "\n".join("".join("##" if v else "  " for v in row) for row in padded)
    if len(padded) % 2:
        padded.append([0] * len(padded[0]))
    lines = []
    for i in range(0, len(padded), 2):
        top, bottom = padded[i], padded[i + 1]
        line = []
        for t, b in zip(top, bottom):
            if t and b:
                line.append("\u2588")
            elif t:
                line.append("\u2580")
            elif b:
                line.append("\u2584")
            else:
                line.append(" ")
        lines.append("".join(line))
    return "\n".join(lines)


def to_svg(matrix: List[List[int]], scale: int = 4, quiet: int = 4) -> str:
    """Minimal SVG. Self-contained: no external CSS, fonts or images."""
    size = len(matrix)
    total = (size + quiet * 2) * scale
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="{total}" '
        f'viewBox="0 0 {total} {total}" shape-rendering="crispEdges">',
        f'<rect width="{total}" height="{total}" fill="#ffffff"/>',
        '<g fill="#000000">',
    ]
    for r, row in enumerate(matrix):
        c = 0
        while c < size:
            if row[c]:
                start = c
                while c < size and row[c]:
                    c += 1
                parts.append(
                    f'<rect x="{(start + quiet) * scale}" y="{(r + quiet) * scale}" '
                    f'width="{(c - start) * scale}" height="{scale}"/>'
                )
            else:
                c += 1
    parts.append("</g></svg>")
    return "".join(parts)


def to_pbm(matrix: List[List[int]], quiet: int = 4) -> bytes:
    """Portable bitmap - the simplest possible image file, no libraries."""
    size = len(matrix) + quiet * 2
    rows = [[0] * size for _ in range(quiet)]
    for row in matrix:
        rows.append([0] * quiet + list(row) + [0] * quiet)
    rows += [[0] * size for _ in range(quiet)]
    body = "\n".join(" ".join(str(v) for v in row) for row in rows)
    return f"P1\n{size} {size}\n{body}\n".encode("ascii")
