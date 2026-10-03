"""Pure matching primitives on the normalized match view.

Normalization (per code point, 1:1, so code-point indices are preserved):
  fullwidth digits U+FF10..U+FF19 -> ASCII '0'..'9'
  fullwidth hyphen U+FF0D         -> '-'
  no-break space U+00A0           -> ' '
Everything else is unchanged.
"""

from __future__ import annotations

#: Maximum length (in view code points) of any single candidate body:
#: 19 digits + 18 separators for bank cards.
MAX_MATCH_LEN = 37

#: View code points that must be available from a start position before it
#: can be evaluated (max body + one boundary char).
LOOKAHEAD = MAX_MATCH_LEN + 1

_TRANSLATION = {0xFF10 + i: str(i) for i in range(10)}
_TRANSLATION[0xFF0D] = "-"
_TRANSLATION[0x00A0] = " "


def normalize(text: str) -> str:
    """Return the match view for ``text`` (same number of code points)."""
    return text.translate(_TRANSLATION)


def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _is_ssn(view: str, s: int, n: int) -> bool:
    # ddd-dd-dddd
    if s + 11 > n:
        return False
    if view[s + 3] != "-" or view[s + 6] != "-":
        return False
    for k in (0, 1, 2, 4, 5, 7, 8, 9, 10):
        if not _is_digit(view[s + k]):
            return False
    if s + 11 < n and _is_digit(view[s + 11]):
        return False
    return True


def _card_ends(view: str, s: int, n: int) -> list[int]:
    """All bank-card match ends starting at ``s`` (13..19 digits, an optional
    single space/hyphen between adjacent digits, Luhn-valid, right neighbour
    not a digit)."""
    ends: list[int] = []
    i = s
    count = 0
    sum_odd = sum_even = 0  # undoubled sums at odd/even 1-based positions
    dbl_odd = dbl_even = 0  # doubled sums at odd/even 1-based positions
    while True:
        if i >= n:
            break
        ch = view[i]
        if not _is_digit(ch):
            break
        v = ord(ch) - 48
        count += 1
        d = v + v
        if d > 9:
            d -= 9
        if count & 1:
            sum_odd += v
            dbl_odd += d
        else:
            sum_even += v
            dbl_even += d
        i += 1
        if 13 <= count <= 19:
            if i >= n or not _is_digit(view[i]):
                # Rightmost digit is not doubled; doubling alternates.
                total = (sum_odd + dbl_even) if (count & 1) else (dbl_odd + sum_even)
                if total % 10 == 0:
                    ends.append(i)
        if count == 19:
            break
        # Try to extend: optional single separator followed by a digit.
        if i >= n:
            break
        ch = view[i]
        if ch == " " or ch == "-":
            if i + 1 < n and _is_digit(view[i + 1]):
                i += 1
                continue
            break
        if not _is_digit(ch):
            break
        # Adjacent digit: continue without a separator.
    return ends


def match_ends_at(view: str, s: int, left: str | None) -> list[int]:
    """Return end indices (exclusive, as indices into ``view``) of every
    match starting at view index ``s``.

    ``left`` is the view char at ``s - 1`` (``None`` at text start).
    Indices ``>= len(view)`` are treated as the edge of the text.
    The caller must guarantee that at least LOOKAHEAD view chars from ``s``
    are present, unless the text has ended.
    """
    if left is not None and _is_digit(left):
        return []
    if s >= len(view) or not _is_digit(view[s]):
        return []
    n = len(view)
    ends = _card_ends(view, s, n)
    if _is_ssn(view, s, n):
        ends.append(s + 11)
    return ends
