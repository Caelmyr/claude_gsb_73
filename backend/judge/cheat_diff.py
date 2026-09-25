"""两份疑似抄袭代码的相似度明细与行级对比。

防作弊判定（backend.judge.cheat）只产出「归一化代码 + SimHash/Jaccard」
的一个相似度数值；本模块负责把判定依据以人类可读的方式展开，供管理员
在报告详情中核对：

  1. 原文 / 归一化文本上的多维度相似度；
  2. difflib 行级对比（并排视图，标注相同/增删行）；
  3. 最长公共行块（直接标出大段雷同代码）。

本模块只做展示用的计算，绝不参与 detect_similarity 的判定，
因此不会影响既有的防作弊结果。
"""
import difflib
import re

from backend.judge.cheat import normalize_code
from backend.utils import truncate

# 详情里单文件最多保留的行数，避免极端长代码撑爆响应
_MAX_LINES = 1200
# 公共行块至少这么多行才算「雷同片段」
_MIN_MATCH_LINES = 2
_WS_RE = re.compile(r"[ \t]+")


def _lines(code):
    """把源码切成行，并去掉行尾空白；超长截断。"""
    if not code:
        return []
    lines = code.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) > _MAX_LINES:
        lines = lines[:_MAX_LINES] + ["……（代码过长，已截断）"]
    return [_WS_RE.sub(" ", ln.rstrip()) for ln in lines]


def _ratio(a, b):
    if not a or not b:
        return 0.0
    return round(difflib.SequenceMatcher(None, a, b, autojunk=False).ratio(), 4)


def side_by_side(code_a, code_b):
    """生成行级并排对比。

    返回行列表，每行：{type, a: {no,text}|None, b: {no,text}|None}
      type: equal / delete（仅 A 有）/ insert（仅 B 有）/ replace
    """
    la, lb = _lines(code_a), _lines(code_b)
    matcher = difflib.SequenceMatcher(None, la, lb, autojunk=False)
    rows = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append({
                    "type": "equal",
                    "a": {"no": i1 + k + 1, "text": la[i1 + k]},
                    "b": {"no": j1 + k + 1, "text": lb[j1 + k]},
                })
        else:
            span = max(i2 - i1, j2 - j1)
            for k in range(span):
                left = la[i1 + k] if k < i2 - i1 else None
                right = lb[j1 + k] if k < j2 - j1 else None
                rows.append({
                    "type": tag,
                    "a": {"no": i1 + k + 1, "text": left} if left is not None else None,
                    "b": {"no": j1 + k + 1, "text": right} if right is not None else None,
                })
    return rows


def matched_blocks(code_a, code_b):
    """提取两份代码中较长的公共行块（雷同片段）。"""
    la, lb = _lines(code_a), _lines(code_b)
    matcher = difflib.SequenceMatcher(None, la, lb, autojunk=False)
    blocks = []
    for blk in matcher.get_matching_blocks():
        if blk.size < _MIN_MATCH_LINES:
            continue
        # 跳过纯空白行组成的块
        text = [la[blk.a + k] for k in range(blk.size)]
        if not any(t.strip() for t in text):
            continue
        blocks.append({
            "a_start": blk.a + 1,
            "b_start": blk.b + 1,
            "lines": min(blk.size, 200),
            "preview": "\n".join(text[:12]),
            "truncated": blk.size > 12,
        })
    blocks.sort(key=lambda x: -x["lines"])
    return blocks[:20]


def build_diff(code_a, code_b, detected_similarity=None):
    """组装一份报告详情所需的全部对比数据。"""
    code_a = truncate(code_a or "", 100000)
    code_b = truncate(code_b or "", 100000)
    norm_a, norm_b = normalize_code(code_a), normalize_code(code_b)
    data = {
        "similarity": {
            # 判定时使用的归一化 Jaccard 相似度（由检测流程传入，原样展示）
            "detected": detected_similarity,
            # 以下仅为详情参考，不参与任何判定
            "raw_line": _ratio(_lines(code_a), _lines(code_b)),
            "normalized": _ratio(norm_a, norm_b),
        },
        "a": {"truncated": len(code_a or "") >= 100000,
              "line_count": len(_lines(code_a))},
        "b": {"truncated": len(code_b or "") >= 100000,
              "line_count": len(_lines(code_b))},
        "rows": side_by_side(code_a, code_b),
        "matched_blocks": matched_blocks(code_a, code_b),
    }
    return data
