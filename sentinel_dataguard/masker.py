"""Streaming incremental PII masker.

Design notes
------------
The input byte stream is decoded incrementally (chunk boundaries may split
multi-byte UTF-8 characters) and normalized 1:1 per code point into a match
view (fullwidth digits -> ASCII digits, U+FF0D -> '-', U+00A0 -> ' ').

Every view position that can start a match (a digit) is evaluated exactly
once, in stream order, and only once at least LOOKAHEAD view chars past it
are available (or the stream ended).  Because every candidate body is at
most 37 view chars, decisions never depend on data further ahead, so the
output is identical for any chunking of the same input.

Matches are merged into redaction regions as they are found.  While a
region is open, covered original bytes are discarded as the scan pointer
advances; only a constant-size state (start byte, end byte, end view
index) is kept, so arbitrarily long overlapping chains use O(1) memory.
Undecided original text held between calls is bounded (well under 512
bytes), and safe text is emitted after at most LOOKAHEAD code points.
"""

from __future__ import annotations

import codecs
import re

from ._matching import LOOKAHEAD, match_ends_at, normalize

#: Replacement token emitted for every merged redaction region.
REDACTED_TOKEN = b"[REDACTED]"

_DIGIT_RE = re.compile("[0-9]")

#: Bytes of caller input decoded per internal processing step.  Keeps
#: transient working copies proportional to the current input block, not
#: to the cumulative stream.
_DECODE_SLICE = 4096


class Masker:
    """Incremental PII masker.

    feed(data) -> (bytes, list[tuple[int, int]])
    finish()   -> (bytes, list[tuple[int, int]])

    Returned byte chunks concatenate to the full masked output; returned
    intervals concatenate to the full redaction list, using absolute byte
    offsets of the original input stream (start inclusive, end exclusive).
    """

    def __init__(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._orig = ""  # pending original text, aligned with _view
        self._view = ""  # pending normalized match view
        self._front = 0  # view index of _view[0]
        self._front_byte = 0  # absolute byte offset of _view[0]
        self._scan = 0  # next view index to evaluate as a candidate start
        self._left: str | None = None  # view char at _scan - 1
        # Open redaction region: [start_byte, end_byte, end_view_index].
        # Invariant: while a region is open, _front >= its start view index.
        self._region: list | None = None
        self._finished = False

    # ------------------------------------------------------------------ API

    def feed(self, data: bytes) -> tuple[bytes, list[tuple[int, int]]]:
        if self._finished:
            raise ValueError("feed() after finish()")
        data = bytes(data)
        out = bytearray()
        intervals: list[tuple[int, int]] = []
        for pos in range(0, len(data), _DECODE_SLICE):
            text = self._decoder.decode(data[pos : pos + _DECODE_SLICE], False)
            if text:
                self._orig += text
                self._view += normalize(text)
                self._process(False, out, intervals)
        return bytes(out), intervals

    def finish(self) -> tuple[bytes, list[tuple[int, int]]]:
        if self._finished:
            raise ValueError("finish() called twice")
        self._finished = True
        out = bytearray()
        intervals: list[tuple[int, int]] = []
        text = self._decoder.decode(b"", True)
        if text:
            self._orig += text
            self._view += normalize(text)
        self._process(True, out, intervals)
        return bytes(out), intervals

    @property
    def pending_original_bytes(self) -> int:
        """Bytes of undecided original input currently held (for tests)."""
        buffered = len(self._decoder.getstate()[0])
        return len(self._orig.encode("utf-8")) + buffered

    # ------------------------------------------------------------- internals

    def _process(
        self, eos: bool, out: bytearray, intervals: list[tuple[int, int]]
    ) -> None:
        while True:
            if self._region is None:
                if not self._step_plain(out, eos):
                    return
            else:
                if not self._step_region(out, intervals, eos):
                    return

    def _step_plain(self, out: bytearray, eos: bool) -> bool:
        m = _DIGIT_RE.search(self._view, self._scan - self._front)
        if m is None:
            # No candidate start remains: everything pending is safe text.
            end = self._front + len(self._view)
            if end > self._front:
                self._left = self._view[-1]
                self._emit_upto(end, out)
                self._scan = end
            return False
        d = self._front + m.start()
        if d > self._front:
            # Positions before d cannot start a match: emit them.
            self._left = self._view[d - 1 - self._front]
            self._emit_upto(d, out)
            self._scan = d
        if len(self._view) - (d - self._front) < LOOKAHEAD and not eos:
            return False  # wait for more lookahead
        ends = match_ends_at(self._view, d - self._front, self._left)
        self._left = self._view[d - self._front]
        self._scan = d + 1
        if ends:
            e = self._front + max(ends)
            start_byte = self._front_byte  # _front == d here
            end_byte = start_byte + len(
                self._orig[: e - self._front].encode("utf-8")
            )
            self._region = [start_byte, end_byte, e]
        return True

    def _step_region(
        self, out: bytearray, intervals: list[tuple[int, int]], eos: bool
    ) -> bool:
        start_byte, end_byte, end_view = self._region
        # Pending positions before the scan pointer are covered: drop them.
        self._drop_upto(self._scan)
        # Find the next possible match start inside the region tail.
        m = _DIGIT_RE.search(self._view, self._scan - self._front)
        d = None
        if m is not None:
            cand = self._front + m.start()
            if cand < end_view:
                d = cand
        if d is None:
            # No start position inside the region can still extend it.
            out += REDACTED_TOKEN
            intervals.append((start_byte, end_byte))
            if end_view > self._scan:
                self._left = self._view[end_view - 1 - self._front]
            self._drop_upto(end_view)
            self._scan = end_view
            self._region = None
            return True
        if d > self._scan:
            self._left = self._view[d - 1 - self._front]
            self._scan = d
        if len(self._view) - (d - self._front) < LOOKAHEAD and not eos:
            return False  # wait for more lookahead
        ends = match_ends_at(self._view, d - self._front, self._left)
        self._left = self._view[d - self._front]
        self._scan = d + 1
        if ends:
            e = self._front + max(ends)
            if e > end_view:
                # The match starts inside the region, so it always merges.
                match_start_byte = self._front_byte + len(
                    self._orig[: d - self._front].encode("utf-8")
                )
                self._region[1] = match_start_byte + len(
                    self._orig[d - self._front : e - self._front].encode("utf-8")
                )
                self._region[2] = e
        return True

    def _emit_upto(self, idx: int, out: bytearray) -> None:
        k = idx - self._front
        if k <= 0:
            return
        data = self._orig[:k].encode("utf-8")
        out += data
        self._front_byte += len(data)
        self._orig = self._orig[k:]
        self._view = self._view[k:]
        self._front = idx

    def _drop_upto(self, idx: int) -> None:
        k = idx - self._front
        if k <= 0:
            return
        self._front_byte += len(self._orig[:k].encode("utf-8"))
        self._orig = self._orig[k:]
        self._view = self._view[k:]
        self._front = idx
