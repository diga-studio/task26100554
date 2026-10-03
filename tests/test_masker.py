"""Tests for sentinel_dataguard.Masker.

Run from the repository root:
    python3 -m unittest discover -s tests -v
"""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel_dataguard import REDACTED_TOKEN, Masker
from sentinel_dataguard._matching import match_ends_at, normalize

FW_DIGIT = lambda ds: "".join(chr(0xFF10 + int(d)) for d in ds)
FW_HYPHEN = chr(0xFF0D)
NBSP = chr(0x00A0)


def reference_mask(data: bytes):
    """Independent whole-string reference: find every match on the full
    normalized view, merge overlapping intervals, redact."""
    text = data.decode("utf-8")
    view = normalize(text)
    byte_off = [0] * (len(text) + 1)
    off = 0
    for i, ch in enumerate(text):
        byte_off[i] = off
        off += len(ch.encode("utf-8"))
    byte_off[len(text)] = off
    hits = []
    for s in range(len(view)):
        left = view[s - 1] if s > 0 else None
        for e in match_ends_at(view, s, left):
            hits.append((s, e))
    hits.sort()
    merged = []
    for s, e in hits:
        if merged and s < merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1][1] = e
        else:
            merged.append([s, e])
    out = bytearray()
    intervals = []
    pos = 0
    for s, e in merged:
        out += text[pos:s].encode("utf-8")
        out += REDACTED_TOKEN
        intervals.append((byte_off[s], byte_off[e]))
        pos = e
    out += text[pos:].encode("utf-8")
    return bytes(out), intervals


def run_chunked(data: bytes, chunk_sizes):
    m = Masker()
    out = bytearray()
    intervals = []
    pos = 0
    for size in chunk_sizes:
        o, iv = m.feed(data[pos : pos + size])
        out += o
        intervals += iv
        pos += size
    if pos < len(data):
        o, iv = m.feed(data[pos:])
        out += o
        intervals += iv
    o, iv = m.finish()
    out += o
    intervals += iv
    return bytes(out), intervals


def chunkings(data: bytes):
    yield [len(data)]  # whole input at once
    yield [1] * len(data)  # one byte at a time (splits multibyte chars)
    rng = random.Random(20261005)
    for _ in range(3):
        sizes = []
        remaining = len(data)
        while remaining > 0:
            s = min(remaining, rng.randint(1, 23))
            sizes.append(s)
            remaining -= s
        yield sizes


class MatchPrimitivesTest(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize(FW_DIGIT("0123456789")), "0123456789")
        self.assertEqual(normalize(FW_HYPHEN), "-")
        self.assertEqual(normalize(NBSP), " ")
        self.assertEqual(normalize("a-b"), "a-b")  # U+2010 untouched

    def test_ssn(self):
        self.assertEqual(match_ends_at("123-45-6789", 0, None), [11])
        self.assertEqual(match_ends_at("1123-45-6789", 1, "1"), [])
        self.assertEqual(match_ends_at("123-45-67890", 0, None), [])
        self.assertEqual(match_ends_at("123-45-678", 0, None), [])

    def test_card(self):
        self.assertEqual(match_ends_at("4111111111111111", 0, None), [16])
        self.assertEqual(match_ends_at("4111 1111 1111 1111", 0, None), [19])
        self.assertEqual(match_ends_at("4111-1111-1111-1111", 0, None), [19])
        self.assertEqual(match_ends_at("4111 1111 1111 1112", 0, None), [])
        self.assertEqual(match_ends_at("0000000000000", 0, None), [13])
        self.assertEqual(match_ends_at("0000000000001", 0, None), [])
        self.assertEqual(match_ends_at("00000000000000", 0, None), [14])
        self.assertEqual(match_ends_at("00000000000000000000", 0, None), [])


class MixedTextTest(unittest.TestCase):
    def test_mixed_against_reference(self):
        text = (
            "通知：用户 张三 的 SSN 123-45-6789 已登记；"
            "全角 " + FW_DIGIT("123") + FW_HYPHEN + FW_DIGIT("45")
            + FW_HYPHEN + FW_DIGIT("6789") + " 也应脱敏；"
            "卡号 4111 1111 1111 1111 有效，"
            "而 4111 1111 1111 1112 无效应保留；"
            "连字符卡 4111-1111-1111-1111；"
            "不间断空格卡 4111" + NBSP + "1111" + NBSP + "1111" + NBSP + "1111；"
            "重叠区 000-00-0000-0000；"
            "嵌套 0000000000000-000；"
            "二十个零 00000000000000000000 不命中；"
            "短号 12345 不命中；结尾 000-00-0000"
        )
        data = text.encode("utf-8")
        expected_out, expected_ivs = reference_mask(data)
        # sanity: the reference itself found the key hits
        self.assertEqual(len(expected_ivs), 8, expected_ivs)
        for sizes in chunkings(data):
            out, ivs = run_chunked(data, sizes)
            self.assertEqual(out, expected_out)
            self.assertEqual(ivs, expected_ivs)
        # intervals point at the original PII bytes
        for s, e in expected_ivs:
            self.assertNotIn(REDACTED_TOKEN, data[s:e])
        self.assertNotIn(b"123-45-6789", expected_out)
        self.assertIn("短号 12345 不命中".encode("utf-8"), expected_out)
        self.assertIn(b"4111 1111 1111 1112", expected_out)  # bad Luhn kept

    def test_fuzz_against_reference(self):
        rng = random.Random(9001)
        alphabet = (
            "0123456789 -" + "0123456789" + "ab，。"
            + FW_DIGIT("0123") + FW_HYPHEN + NBSP
        )
        for _ in range(300):
            n = rng.randint(0, 120)
            text = "".join(rng.choice(alphabet) for _ in range(n))
            data = text.encode("utf-8")
            expected_out, expected_ivs = reference_mask(data)
            for sizes in chunkings(data):
                out, ivs = run_chunked(data, sizes)
                self.assertEqual(out, expected_out, text)
                self.assertEqual(ivs, expected_ivs, text)


class BoundaryCommitTest(unittest.TestCase):
    def test_luhn_prefix_killed_by_next_digit(self):
        # 13 zeros pass Luhn, but a 14th digit destroys the boundary;
        # the 14-digit candidate is valid instead.
        m = Masker()
        out1, iv1 = m.feed(b"0000000000000")
        self.assertEqual(iv1, [])
        self.assertEqual(out1, b"")  # nothing committed prematurely
        out2, iv2 = m.feed(b"0")
        self.assertEqual(iv2, [])
        self.assertEqual(out2, b"")
        out3, iv3 = m.feed(" 结尾".encode("utf-8"))
        out4, iv4 = m.finish()
        self.assertEqual(iv1 + iv2 + iv3 + iv4, [(0, 14)])
        self.assertEqual(out1 + out2 + out3 + out4,
                         REDACTED_TOKEN + " 结尾".encode("utf-8"))

    def test_thirteen_zeros_alone_are_hit(self):
        data = b"0000000000000 x"
        out, ivs = run_chunked(data, [1] * len(data))
        self.assertEqual(ivs, [(0, 13)])
        self.assertEqual(out, REDACTED_TOKEN + b" x")

    def test_twenty_zeros_no_hit(self):
        data = b"00000000000000000000"
        for sizes in chunkings(data):
            out, ivs = run_chunked(data, sizes)
            self.assertEqual(out, data)
            self.assertEqual(ivs, [])

    def test_nested_candidates_merge(self):
        # 13-digit candidate [0,13) and 16-digit candidate [0,17) merge.
        data = b"0000000000000-000"
        for sizes in chunkings(data):
            out, ivs = run_chunked(data, sizes)
            self.assertEqual(out, REDACTED_TOKEN)
            self.assertEqual(ivs, [(0, 17)])

    def test_longer_candidate_covers_following_content(self):
        # "0000000000000" alone would be a hit; followed by "000" it becomes
        # part of a longer 16-digit hit covering the extra digits.
        data = b"0000000000000" + b"000" + b"!"
        out, ivs = run_chunked(data, [13, 3, 1])
        self.assertEqual(out, REDACTED_TOKEN + b"!")
        self.assertEqual(ivs, [(0, 16)])


class OverlapChainTest(unittest.TestCase):
    def test_megabyte_chain_single_interval(self):
        data = ("0000-" * 210000 + "0000").encode("utf-8")
        self.assertGreaterEqual(len(data), 1 << 20)
        m = Masker()
        out = bytearray()
        ivs = []
        max_pending = 0
        for pos in range(0, len(data), 65536):
            o, iv = m.feed(data[pos : pos + 65536])
            out += o
            ivs += iv
            max_pending = max(max_pending, m.pending_original_bytes)
            # the chain never closes mid-stream: nothing may be committed
            self.assertEqual(o, b"")
            self.assertEqual(iv, [])
        o, iv = m.finish()
        out += o
        ivs += iv
        self.assertEqual(bytes(out), REDACTED_TOKEN)
        self.assertEqual(ivs, [(0, len(data))])
        self.assertLessEqual(max_pending, 512)

    def test_chain_odd_chunks(self):
        data = ("0000-" * 20000 + "0000").encode("utf-8")
        out, ivs = run_chunked(data, [7] * (len(data) // 7))
        self.assertEqual(out, REDACTED_TOKEN)
        self.assertEqual(ivs, [(0, len(data))])


class StreamingStressTest(unittest.TestCase):
    def test_64mib_streaming_bounded_memory(self):
        filler_unit = (
            "普通通知文本 lorem ipsum dolor sit amet，没有任何敏感号码。\n"
        ).encode("utf-8")
        chunk_size = 1 << 20
        total = 64 << 20
        pii_items = [
            ("（卡号 ", "4111 1111 1111 1111", "）"),
            ("（SSN ", "123-45-6789", "）"),
        ]

        def generate():
            # Yields (input_chunk, expected_output_chunk, expected_intervals)
            # without ever holding the full stream in memory.
            produced = 0
            offset = 0
            idx = 0
            next_pii_at = 4 << 20
            while produced < total:
                if produced >= next_pii_at:
                    next_pii_at += 4 << 20
                    pre, pii, suf = pii_items[idx % len(pii_items)]
                    idx += 1
                    chunk = (pre + pii + suf).encode("utf-8")
                    exp = pre.encode("utf-8") + REDACTED_TOKEN + suf.encode("utf-8")
                    start = offset + len(pre.encode("utf-8"))
                    yield chunk, exp, [(start, start + len(pii.encode("utf-8")))]
                    offset += len(chunk)
                    produced += len(chunk)
                else:
                    remaining = total - produced
                    units = min(chunk_size // len(filler_unit),
                                remaining // len(filler_unit))
                    chunk = filler_unit * units if units else b"x" * remaining
                    yield chunk, chunk, []
                    offset += len(chunk)
                    produced += len(chunk)

        m = Masker()
        expected_pending = bytearray()  # bounded: drained as the masker emits
        expected_ivs = []
        got_ivs = []
        max_pending = 0
        fed = emitted = 0
        filler_outputs = 0
        for chunk, exp, ivs in generate():
            out, got = m.feed(chunk)
            fed += len(chunk)
            emitted += len(out)
            expected_pending += exp
            self.assertEqual(bytes(expected_pending[: len(out)]), out)
            del expected_pending[: len(out)]
            expected_ivs += ivs
            got_ivs += got
            max_pending = max(max_pending, m.pending_original_bytes)
            if not ivs and len(chunk) >= (1 << 19):
                # plain filler must stream out, not be held until finish()
                filler_outputs += 1
                self.assertGreater(len(out), 0)
        out, got = m.finish()
        emitted += len(out)
        self.assertEqual(bytes(expected_pending[: len(out)]), out)
        del expected_pending[: len(out)]
        got_ivs += got
        self.assertEqual(bytes(expected_pending), b"")
        self.assertEqual(fed, total)
        self.assertGreater(filler_outputs, 0)
        self.assertEqual(got_ivs, expected_ivs)
        self.assertGreaterEqual(len(expected_ivs), 8)
        self.assertLessEqual(max_pending, 512)
        # output size = input size - PII bytes + replacement tokens
        pii_bytes = sum(e - s for s, e in expected_ivs)
        self.assertEqual(emitted, total - pii_bytes
                         + len(expected_ivs) * len(REDACTED_TOKEN))


if __name__ == "__main__":
    unittest.main()
