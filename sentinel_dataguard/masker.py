"""Sentinel DataGuard incremental PII masking.

Streaming masker with chunking-independent output:

- ``feed(data)`` accepts a chunk of UTF-8 bytes (chunks may split multi-byte
  characters) and returns ``(safe_bytes, closed_intervals)``.
- ``finish()`` flushes the remainder.

Concatenating the returned bytes yields the full masked output; concatenating
the interval lists yields the full replacement list.  Intervals are absolute
byte offsets into the original input stream, ``[start, end)``.

Internal state is bounded: at most ``_WINDOW_LIMIT`` (112) pending code points
of original text are retained (<= 448 bytes < 512), and unmatched text is
emitted with a delay of at most 112 code points (< 128).
"""

import codecs
import re
from typing import List, Optional, Tuple

__all__ = ["Masker"]

_REDACTED = b"[REDACTED]"

# Matching-view translation: full-width digits -> ASCII, U+FF0D -> '-',
# U+00A0 -> ' '.  Everything else is left unchanged.
_TRANSLATE = {0xFF10 + i: chr(0x30 + i) for i in range(10)}
_TRANSLATE[0xFF0D] = "-"
_TRANSLATE[0x00A0] = " "

_SEPS = frozenset(" -")
_START_RE = re.compile(r"(?<![0-9])[0-9]")

# A card number holds 13..19 digits with at most one separator between
# adjacent digits, so the longest possible match is 19 + 18 = 37 code points.
# An SSN is 11 code points.  To evaluate every candidate starting at position
# p we therefore need the code points up to p + 37 (right-boundary look-ahead
# included).
_MAX_MATCH = 37

# Evaluation is triggered once the pending window reaches this many code
# points.  Keeps pending original text <= 112 * 4 = 448 bytes and the output
# delay <= 112 code points.
_WINDOW_LIMIT = 112


def _is_digit(ch: str) -> bool:
    return "0" <= ch <= "9"


def _luhn_ok(digits) -> bool:
    total = 0
    for idx in range(len(digits) - 1, -1, -1):
        d = ord(digits[idx]) - 0x30
        if (len(digits) - 1 - idx) % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _match_end(norm: str, i: int, length: int) -> Optional[int]:
    """Longest valid match starting at relative index ``i``, or None.

    ``norm`` is the normalized window, ``length`` its length.  Indices at or
    beyond ``length`` are treated as the (permissive) end-of-text edge.
    Returns the exclusive end index (relative to the window) of the longest
    valid candidate; shorter candidates starting at ``i`` are nested inside
    it and therefore irrelevant for merging.
    """
    best: Optional[int] = None

    # SSN: DDD-DD-DDDD
    if i + 11 <= length:
        s = norm
        if (
            _is_digit(s[i])
            and _is_digit(s[i + 1])
            and _is_digit(s[i + 2])
            and s[i + 3] == "-"
            and _is_digit(s[i + 4])
            and _is_digit(s[i + 5])
            and s[i + 6] == "-"
            and _is_digit(s[i + 7])
            and _is_digit(s[i + 8])
            and _is_digit(s[i + 9])
            and _is_digit(s[i + 10])
            and (i + 11 == length or not _is_digit(s[i + 11]))
        ):
            best = i + 11

    # Card: 13..19 digits, at most one separator between adjacent digits.
    digits = [norm[i]]
    pos = i
    while len(digits) < 19:
        nxt = pos + 1
        if nxt < length and _is_digit(norm[nxt]):
            pos = nxt
        elif (
            nxt + 1 < length
            and norm[nxt] in _SEPS
            and _is_digit(norm[nxt + 1])
        ):
            pos = nxt + 1
        else:
            break
        digits.append(norm[pos])
        count = len(digits)
        if count >= 13:
            end = pos + 1
            if end < length and _is_digit(norm[end]):
                continue  # right boundary fails
            if _luhn_ok(digits):
                best = end

    return best


class Masker:
    """Incremental PII masker with bounded memory and no output retraction."""

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._orig = ""  # pending original code points
        self._norm = ""  # pending normalized code points (same length)
        self._base = 0  # absolute code point index of window[0]
        self._base_byte = 0  # absolute byte offset of window[0]
        self._evaluated = 0  # next absolute position to evaluate
        self._emit = 0  # next absolute position to emit
        self._open = False  # a merged interval is currently open
        self._m_start = 0  # open interval start (code point index)
        self._m_end = 0  # open interval end (code point index)
        self._m_start_byte = 0
        self._m_end_byte = 0
        self._finished = False

    # ------------------------------------------------------------------ API

    def feed(self, data: bytes) -> Tuple[bytes, List[Tuple[int, int]]]:
        """Consume one chunk of UTF-8 bytes.

        Returns the newly produced safe bytes and the replacement intervals
        that were determined to be complete during this call.
        """
        if self._finished:
            raise ValueError("feed() called after finish()")
        text = self._decoder.decode(bytes(data), False)
        out: List[bytes] = []
        intervals: List[Tuple[int, int]] = []
        pos = 0
        total = len(text)
        while pos < total:
            room = _WINDOW_LIMIT - len(self._norm)
            if room == 0:
                self._drain(out, intervals)
                continue
            take = min(room, total - pos)
            segment = text[pos : pos + take]
            self._orig += segment
            self._norm += segment.translate(_TRANSLATE)
            pos += take
            if len(self._norm) >= _WINDOW_LIMIT:
                self._drain(out, intervals)
        return b"".join(out), intervals

    def finish(self) -> Tuple[bytes, List[Tuple[int, int]]]:
        """Signal end of input and flush all remaining output."""
        if self._finished:
            raise ValueError("finish() called twice")
        self._finished = True
        tail = self._decoder.decode(b"", True)
        if tail:  # pragma: no cover - input is guaranteed valid UTF-8
            self._orig += tail
            self._norm += tail.translate(_TRANSLATE)
        out: List[bytes] = []
        intervals: List[Tuple[int, int]] = []
        frontier = self._base + len(self._norm) - 1
        self._process(out, intervals, frontier, final=True)
        self._evaluated = frontier + 1
        return b"".join(out), intervals

    # -------------------------------------------------------------- internals

    @property
    def _pending_chars(self) -> int:
        """Number of retained undecided code points (test instrumentation)."""
        return len(self._orig)

    def _drain(self, out: List[bytes], intervals: List[Tuple[int, int]]) -> None:
        frontier = self._base + len(self._norm) - (_MAX_MATCH + 1)
        if frontier < self._evaluated:
            return
        self._process(out, intervals, frontier, final=False)
        self._evaluated = frontier + 1
        self._trim()

    def _trim(self) -> None:
        keep = self._evaluated - 1 - self._base
        if keep > 0:
            self._base_byte += len(self._orig[:keep].encode("utf-8"))
            self._orig = self._orig[keep:]
            self._norm = self._norm[keep:]
            self._base += keep

    def _byte_of(self, pos: int) -> int:
        return self._base_byte + len(self._orig[: pos - self._base].encode("utf-8"))

    def _emit_raw(self, out: List[bytes], start: int, end: int) -> None:
        if end > start:
            out.append(self._orig[start - self._base : end - self._base].encode("utf-8"))

    def _close(self, out: List[bytes], intervals: List[Tuple[int, int]]) -> None:
        out.append(_REDACTED)
        intervals.append((self._m_start_byte, self._m_end_byte))
        self._open = False
        self._emit = self._m_end

    def _process(
        self,
        out: List[bytes],
        intervals: List[Tuple[int, int]],
        frontier: int,
        final: bool,
    ) -> None:
        length = len(self._norm)
        start_idx = self._evaluated - self._base
        if start_idx < 0:
            start_idx = 0
        if start_idx <= frontier - self._base:
            for match in _START_RE.finditer(self._norm, start_idx, length):
                p = match.start() + self._base
                if p > frontier:
                    break
                if self._open and p >= self._m_end:
                    self._close(out, intervals)
                end = _match_end(self._norm, p - self._base, length)
                if end is None:
                    continue
                end += self._base
                if self._open:
                    if end > self._m_end:
                        self._m_end = end
                        self._m_end_byte = self._byte_of(end)
                else:
                    self._emit_raw(out, self._emit, p)
                    self._open = True
                    self._m_start = p
                    self._m_end = end
                    self._m_start_byte = self._byte_of(p)
                    self._m_end_byte = self._byte_of(end)
                    self._emit = p
        if self._open and (final or self._m_end <= frontier):
            self._close(out, intervals)
        if not self._open:
            self._emit_raw(out, self._emit, frontier + 1)
            self._emit = frontier + 1
