"""Tests for sentinel_dataguard.Masker.

Includes an independent whole-string reference implementation used to
cross-check the streaming masker under different chunkings.
"""

import random
import re
import unittest

from sentinel_dataguard import Masker
from sentinel_dataguard.masker import _TRANSLATE

REDACTED = b"[REDACTED]"
SSN_RE = re.compile(r"[0-9]{3}-[0-9]{2}-[0-9]{4}")
CARD_RE = re.compile(r"[0-9](?:[ -]?[0-9]){12,18}")


def is_digit(ch):
    return "0" <= ch <= "9"


def luhn_ok(digits):
    total = 0
    for idx, ch in enumerate(reversed(digits)):
        d = int(ch)
        if idx % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def reference_mask(data):
    """Independent whole-string reference: find every valid interval, merge
    all overlaps, replace each merged interval with [REDACTED]."""
    text = data.decode("utf-8")
    norm = text.translate(_TRANSLATE)
    n = len(norm)
    hits = []
    for p in range(n):
        if not is_digit(norm[p]):
            continue
        if p > 0 and is_digit(norm[p - 1]):
            continue
        for e in range(p + 1, min(n, p + 37) + 1):
            seg = norm[p:e]
            if SSN_RE.fullmatch(seg):
                ok = True
            elif CARD_RE.fullmatch(seg) and luhn_ok([c for c in seg if is_digit(c)]):
                ok = True
            else:
                ok = False
            if ok and (e == n or not is_digit(norm[e])):
                hits.append((p, e))
    merged = []
    for s, e in sorted(hits):
        if merged and s < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    byte_off = [0]
    for ch in text:
        byte_off.append(byte_off[-1] + len(ch.encode("utf-8")))
    out = []
    intervals = []
    pos = 0
    for s, e in merged:
        out.append(text[pos:s].encode("utf-8"))
        out.append(REDACTED)
        intervals.append((byte_off[s], byte_off[e]))
        pos = e
    out.append(text[pos:].encode("utf-8"))
    return b"".join(out), intervals


def run_masker(data, chunk_sizes):
    """Feed ``data`` through a Masker using the given chunk-size sequence."""
    masker = Masker()
    out = []
    intervals = []
    pos = 0
    idx = 0
    while pos < len(data):
        size = chunk_sizes[idx % len(chunk_sizes)]
        idx += 1
        piece = data[pos : pos + size]
        pos += len(piece)
        o, iv = masker.feed(piece)
        out.append(o)
        intervals.extend(iv)
    o, iv = masker.finish()
    out.append(o)
    intervals.extend(iv)
    return b"".join(out), intervals


# A 16-digit Luhn-valid number whose 13-digit prefix is also Luhn-valid.
def find_prefix_trap():
    base = "411111111111"
    prefix = None
    for d in range(10):
        cand = base + str(d)
        if luhn_ok(cand):
            prefix = cand
            break
    assert prefix is not None and len(prefix) == 13
    for suffix in range(1000):
        cand = prefix + "{:03d}".format(suffix)
        if luhn_ok(cand):
            return prefix, cand
    raise AssertionError("no suffix found")  # pragma: no cover


MIXED_TEXT = (
    "123-45-6789 开头边缘。\n"
    "普通 SSN: 123-45-6789。\n"
    "全角 SSN: １２３－４５－６７８９；\n"
    "不换行空格卡号: 4111 1111 1111 1111！\n"
    "全角卡号: ４１１１１１１１１１１１１１１１。\n"
    "无效 Luhn: 4111-1111-1111-1112 应保留。\n"
    "超长数字串: 00000000000000000000 应保留。\n"
    "SSN 与卡号交叠: 55 123-45-6789 118。\n"
    "嵌套候选: 0000000000000 000。\n"
    "多字节🎉字符混合 café 测试。\n"
    "末尾边缘卡号 4111111111111111"
)


class ReferenceCrossCheckTest(unittest.TestCase):
    def test_reference_sanity(self):
        out, intervals = reference_mask(MIXED_TEXT.encode("utf-8"))
        self.assertIn(REDACTED, out)
        self.assertNotIn(b"123-45-6789", out)
        self.assertIn(b"4111-1111-1111-1112", out)  # invalid Luhn preserved
        self.assertIn(b"00000000000000000000", out)  # 20-digit run preserved
        self.assertIn("🎉".encode("utf-8"), out)

    def test_single_feed_matches_reference(self):
        data = MIXED_TEXT.encode("utf-8")
        expected_out, expected_iv = reference_mask(data)
        got_out, got_iv = run_masker(data, [len(data)])
        self.assertEqual(got_out, expected_out)
        self.assertEqual(got_iv, expected_iv)

    def test_single_byte_chunks_match_reference(self):
        data = MIXED_TEXT.encode("utf-8")
        expected_out, expected_iv = reference_mask(data)
        got_out, got_iv = run_masker(data, [1])
        self.assertEqual(got_out, expected_out)
        self.assertEqual(got_iv, expected_iv)

    def test_random_chunks_match_reference(self):
        data = MIXED_TEXT.encode("utf-8")
        expected_out, expected_iv = reference_mask(data)
        for seed in range(5):
            rng = random.Random(seed)
            sizes = [rng.randint(1, 11) for _ in range(64)]
            got_out, got_iv = run_masker(data, sizes)
            self.assertEqual(got_out, expected_out, "seed=%d" % seed)
            self.assertEqual(got_iv, expected_iv, "seed=%d" % seed)


class LuhnPrefixBoundaryTest(unittest.TestCase):
    def test_prefix_not_committed_early(self):
        prefix, full = find_prefix_trap()
        text = "id=" + full + "!"
        data = text.encode("utf-8")
        masker = Masker()
        # Feed everything up to and including the 13-digit Luhn-valid prefix.
        cut = len("id=" + prefix)
        out1, iv1 = masker.feed(data[:cut])
        self.assertEqual(iv1, [])
        self.assertNotIn(prefix.encode(), out1)
        # The rest makes the prefix boundary invalid; the 16-digit number wins.
        out2, iv2 = masker.feed(data[cut:])
        out3, iv3 = masker.finish()
        got_out = out1 + out2 + out3
        got_iv = iv1 + iv2 + iv3
        expected_out, expected_iv = reference_mask(data)
        self.assertEqual(got_out, expected_out)
        self.assertEqual(got_iv, expected_iv)
        self.assertEqual(got_iv, [(3, 3 + len(full))])
        self.assertEqual(got_out, b"id=" + REDACTED + b"!")

    def test_prefix_alone_is_redacted(self):
        prefix, _ = find_prefix_trap()
        data = ("id=" + prefix + "!").encode("utf-8")
        got_out, got_iv = run_masker(data, [3])
        self.assertEqual(got_out, b"id=" + REDACTED + b"!")
        self.assertEqual(got_iv, [(3, 16)])


class OverlapChainTest(unittest.TestCase):
    def test_one_mib_chain_single_interval(self):
        unit = "0000-"
        repeats = (1024 * 1024) // len(unit) + 1
        text = unit * repeats + "0000"
        data = text.encode("ascii")
        self.assertGreaterEqual(len(data), 1024 * 1024)
        masker = Masker()
        max_pending = 0
        step = 65536
        for pos in range(0, len(data), step):
            out, iv = masker.feed(data[pos : pos + step])
            max_pending = max(max_pending, masker._pending_chars)
            self.assertEqual(out, b"")  # nothing may escape the open interval
            self.assertEqual(iv, [])
        out, iv = masker.finish()
        self.assertEqual(out, REDACTED)
        self.assertEqual(iv, [(0, len(data))])
        self.assertLessEqual(max_pending, 112)
        self.assertLessEqual(max_pending * 4, 512)

    def test_chain_chunking_independent(self):
        text = "0000-" * 2000 + "0000"
        data = text.encode("ascii")
        for size in (1, 3, 7, 4096):
            got_out, got_iv = run_masker(data, [size])
            self.assertEqual(got_out, REDACTED)
            self.assertEqual(got_iv, [(0, len(data))])


class EmissionDelayTest(unittest.TestCase):
    def test_unmatched_text_flows_out(self):
        masker = Masker()
        emitted = 0
        # 200 safe code points fed one at a time must not all be withheld.
        for _ in range(200):
            out, iv = masker.feed("安".encode("utf-8"))
            emitted += len(out)
            self.assertEqual(iv, [])
        self.assertGreaterEqual(emitted, (200 - 128) * 3)
        out, _ = masker.finish()
        self.assertEqual(emitted + len(out), 200 * 3)


class FuzzTest(unittest.TestCase):
    def test_random_texts_match_reference(self):
        alphabet = (
            list("0123456789") * 3
            + list("- -")
            + ["　", "５", "９", "－", " ", "a", "Z", "。", "🎉", "x"]
        )
        rng = random.Random(20261005)
        for trial in range(300):
            n = rng.randint(0, 120)
            text = "".join(rng.choice(alphabet) for _ in range(n))
            data = text.encode("utf-8")
            expected_out, expected_iv = reference_mask(data)
            sizes = [rng.randint(1, 9) for _ in range(8)]
            got_out, got_iv = run_masker(data, sizes)
            self.assertEqual(got_out, expected_out, "trial=%d text=%r" % (trial, text))
            self.assertEqual(got_iv, expected_iv, "trial=%d text=%r" % (trial, text))


class StreamingStressTest(unittest.TestCase):
    def test_64_mib_bounded_memory(self):
        safe = (
            "lorem ipsum dolor sit amet consectetur adipiscing elit sed do "
            "eiusmod tempor incididunt ut labore et dolore magna aliqua "
        )
        marker = "ssn 123-45-6789. "
        segment = (safe * 500 + marker).encode("ascii")
        total_target = 64 * 1024 * 1024

        def chunks():
            sent = 0
            while sent < total_target:
                piece = segment[: min(len(segment), total_target - sent)]
                sent += len(piece)
                yield piece

        masker = Masker()
        fed = 0
        emitted = 0
        n_intervals = 0
        interval_bytes = 0
        max_pending = 0
        max_lag = 0
        for piece in chunks():
            fed += len(piece)
            out, iv = masker.feed(piece)
            emitted += len(out)
            n_intervals += len(iv)
            interval_bytes += sum(e - s for s, e in iv)
            max_pending = max(max_pending, masker._pending_chars)
            max_lag = max(max_lag, fed - emitted)
            del out, iv
        out, iv = masker.finish()
        emitted += len(out)
        n_intervals += len(iv)
        interval_bytes += sum(e - s for s, e in iv)

        n_segments = -(-total_target // len(segment))
        full_segments = total_target // len(segment)
        # Markers: one per fully emitted segment; the final partial segment
        # may or may not contain a marker depending on its length.
        tail = total_target - full_segments * len(segment)
        expected_markers = full_segments + (1 if tail > len(safe * 500) else 0)
        self.assertEqual(n_intervals, expected_markers)
        self.assertEqual(interval_bytes, expected_markers * len("123-45-6789"))
        self.assertEqual(emitted, fed - interval_bytes + n_intervals * len(REDACTED))
        self.assertLessEqual(max_pending, 112)
        # Unmatched text must flow out continuously (bounded lag), proving
        # output is not deferred to finish().
        self.assertLessEqual(max_lag, 4096)
        self.assertGreater(n_segments, 0)


class EdgeCaseTest(unittest.TestCase):
    def test_empty_input(self):
        masker = Masker()
        self.assertEqual(masker.finish(), (b"", []))

    def test_feed_after_finish_raises(self):
        masker = Masker()
        masker.finish()
        with self.assertRaises(ValueError):
            masker.feed(b"x")

    def test_multibyte_split_across_feeds(self):
        data = "卡号🎉１２３－４５－６７８９完".encode("utf-8")
        expected_out, expected_iv = reference_mask(data)
        for size in (1, 2, 3, 5):
            got_out, got_iv = run_masker(data, [size])
            self.assertEqual(got_out, expected_out)
            self.assertEqual(got_iv, expected_iv)


if __name__ == "__main__":
    unittest.main()
