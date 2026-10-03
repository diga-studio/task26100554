# Sentinel DataGuard 增量 PII 脱敏库

对完成模板变量替换后的通知正文做**流式** PII 脱敏。无论输入如何切块，
最终输出字节与替换区间完全一致；任何已返回的字节都不需要撤回或修正。

## 识别规则

匹配前先把正文归一化为匹配视图（逐码点一一对应，不改变码点数量）：
全角数字 → ASCII 数字，全角连字符 U+FF0D → `-`，不换行空格 U+00A0 → 空格。

- **SSN**：`ddd-dd-dddd`（不检查号码分配规则）。
- **银行卡号**：13–19 位数字，相邻数字间可无分隔符或有一个空格/连字符；
  去掉分隔符后必须通过 Luhn 校验。
- 命中区间左右紧邻字符不得是数字（正文边缘视为满足，不跳过空格/连字符）。
- 同一原文上的所有命中（含嵌套、跨类型交叠）合并为若干区间，
  每个合并区间整体替换为 `[REDACTED]`，并只报告一个区间。

## 使用

```python
from sentinel_dataguard import Masker

masker = Masker()
out = bytearray()
intervals = []
for chunk in source:                      # chunk: bytes，可在多字节字符内部切开
    data, done = masker.feed(chunk)       # data: 安全字节；done: 已确定的区间
    out += data
    intervals += done
data, done = masker.finish()              # 输入结束，取走剩余结果
out += data
intervals += done
# bytes(out)   -> 供调用方持久化的脱敏结果
# intervals    -> [(start, end), ...] 原始输入字节流的绝对偏移，前闭后开
```

- 各次返回的字节按序拼接即为完整结果；区间按序连接即为完整替换清单。
- `finish()` 之后再调用 `feed()`/`finish()` 会抛出 `ValueError`。

## 流式保证

- 不缓存完整正文或完整命中清单；未决原文在任意调用返回后不超过 512 字节
  （可通过 `masker.pending_original_bytes` 观察）。
- 未命中文本最多延迟 38 个码点输出（最长候选 19 位数字 + 18 个分隔符
  + 1 个边界字符），不会拖到 `finish()`。
- 连续交叠命中形成的任意长合并区间只占 O(1) 内部状态。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖：独立整串参考判定核对混合正文（全角字符、两类 PII 交叠、无效 Luhn）
在整串/单字节/随机切块下的一致性；随机文本模糊测试；Luhn 前缀被后续数字
破坏边界且更长候选覆盖后续内容；1 MiB `0000-` 交叠链只产生一个区间；
64 MiB 生成器流式输入验证持续输出与有界内存。
