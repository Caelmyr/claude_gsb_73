"""防作弊检测。

主要手段：
  1. 代码相似度检测：对源码做归一化（去注释、去空白、统一标识符）后计算
     SimHash 指纹，再对相近指纹做精确相似度（汉明距离）聚类；
  2. 时间窗检测：同一题目在短时间内出现高度相似提交则标记；
  3. 完全一致检测：直接哈希比对，捕获原样抄袭。

检测结果写入 data/settings/cheat_report.json，并可在提交记录中标记。

报告同时承载「申诉」数据：被标记用户可提交申诉说明，管理员复核后
给出维持原判 / 撤销标记的结论。申诉字段与检测流程完全解耦：
  - normalize_code / detect_similarity 等判定逻辑不因申诉改动；
  - 申诉、复核只更新报告内的 appeal 字段与报告状态；
  - 提交分片上的 similar 标记保持原样，复核结论只在报告中体现。
"""
import difflib
import hashlib
import os
import re

from backend import config
from backend.storage import read_json, locked_update
from backend.utils import now_iso, gen_id

REPORT_FILE = os.path.join(config.SETTINGS_DIR, "cheat_report.json")

# 注释 / 字符串 / 空白 的正则（语言相关，做尽力归一化）
_COMMENT_RE = re.compile(r"(#.*$|//.*$|/\*.*?\*/|/\*.*)", re.MULTILINE | re.DOTALL)
_IDENT_RE = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")
_WS_RE = re.compile(r"\s+")


def normalize_code(code):
    """归一化源码：去注释、去空白、统一标识符为占位符。

    归一化后保留结构信息（关键字、操作符、括号、字符串字面量），
    使「改变量名/换行/加注释」的抄袭能被识别。
    """
    if not code:
        return ""
    code = _COMMENT_RE.sub(" ", code)
    # 字符串字面量统一为占位符（保留结构但不因文案差异误判）
    code = re.sub(r'"[^"\n]*"', '"S"', code)
    code = re.sub(r"'[^'\n]*'", "'S'", code)
    # 数字统一
    code = re.sub(r"\b\d+(\.\d+)?\b", "N", code)
    # 标识符统一为 V
    code = _IDENT_RE.sub("V", code)
    # 折叠空白
    code = _WS_RE.sub("", code)
    return code


def _simhash(text, bits=64):
    """计算文本的 SimHash 指纹（64bit）。"""
    v = [0] * bits
    # 以 3-gram 作为特征
    grams = set()
    n = len(text)
    for i in range(max(1, n - 2)):
        grams.add(text[i:i + 3])
    if not grams:
        grams.add(text)
    for g in grams:
        h = int(hashlib.md5(g.encode("utf-8")).hexdigest()[:16], 16)
        for b in range(bits):
            if (h >> b) & 1:
                v[b] += 1
            else:
                v[b] -= 1
    fp = 0
    for b in range(bits):
        if v[b] > 0:
            fp |= (1 << b)
    return fp


def _hamming(a, b):
    return bin(a ^ b).count("1")


def _record_for(submission):
    return {
        "id": submission["id"],
        "user_id": submission["user_id"],
        "username": submission.get("username", ""),
        "problem_id": submission.get("problem_id", ""),
        "language": submission.get("language", ""),
        "created_at": submission.get("created_at", ""),
    }


def detect_similarity(submission, all_recent):
    """对一次新提交与近期提交做相似度检测。

    返回 (is_cheat: bool, similar_pair: dict|None)。
    """
    code_norm = normalize_code(submission.get("code", ""))
    if len(code_norm) < 50:
        return False, None
    fp = _simhash(code_norm)

    best = None
    best_score = 0.0
    threshold = float(
        config.DEFAULT_SETTINGS["anti_cheat"]["similarity_threshold"]
    )
    for other in all_recent:
        if other.get("id") == submission.get("id"):
            continue
        if other.get("problem_id") != submission.get("problem_id"):
            continue
        if other.get("user_id") == submission.get("user_id"):
            continue
        o_norm = normalize_code(other.get("code", ""))
        if len(o_norm) < 50:
            continue
        o_fp = _simhash(o_norm)
        ham = _hamming(fp, o_fp)
        # 汉明距离 -> 近似相似度：<=3 视为高相似，<=10 需精确验证
        if ham > 12:
            continue
        if o_norm == code_norm:
            sim = 1.0
        else:
            # 精确 Jaccard（3-gram）
            a = set(code_norm[i:i + 3] for i in range(max(1, len(code_norm) - 2)))
            b = set(o_norm[i:i + 3] for i in range(max(1, len(o_norm) - 2)))
            if not a or not b:
                sim = 0.0
            else:
                sim = len(a & b) / len(a | b)
        if sim > best_score:
            best_score = sim
            best = {"a": _record_for(submission), "b": _record_for(other), "similarity": round(sim, 4)}
    if best and best_score >= threshold:
        return True, best
    return False, best


def record_report(entry):
    """把一次疑似作弊对写入报告文件。"""
    # 申诉相关字段在写入时给默认值，与检测结果互不影响
    entry.setdefault("rid", gen_id("cr"))
    entry.setdefault("detected_at", entry.get("a", {}).get("created_at") or now_iso())
    entry.setdefault("status", "open")          # open | upheld | revoked
    entry.setdefault("appeal", None)
    entry.setdefault("reviews", [])

    def _upd(d):
        if d is None:
            d = {"reports": [], "updated_at": ""}
        d.setdefault("reports", []).insert(0, entry)
        d["reports"] = d["reports"][:500]
        d["updated_at"] = now_iso()
        return d
    locked_update(REPORT_FILE, _upd, default=None)
    return entry


def _legacy_rid(report, index):
    """为升级前产生的报告生成稳定 ID（同一条报告每次回填结果一致）。"""
    a = report.get("a") or {}
    raw = "{}|{}|{}|{}".format(
        index, a.get("id", ""), (report.get("b") or {}).get("id", ""),
        report.get("similarity", ""),
    )
    return "cr" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _backfill(reports):
    """补齐历史报告缺失的 rid / 申诉字段，保证后续更新有稳定键。"""
    for i, r in enumerate(reports):
        if not r.get("rid"):
            r["rid"] = _legacy_rid(r, i)
        r.setdefault("detected_at", (r.get("a") or {}).get("created_at") or "")
        r.setdefault("status", "open")
        r.setdefault("appeal", None)
        r.setdefault("reviews", [])
    return reports


def get_report():
    """读取防作弊报告（读取时补齐历史数据的缺失字段）。"""
    data = read_json(REPORT_FILE, {"reports": [], "updated_at": ""})
    if not data:
        data = {"reports": [], "updated_at": ""}
    reports = _backfill(data.get("reports", []))
    return {"reports": reports, "updated_at": data.get("updated_at", "")}


def find_report(rid):
    """按 rid 查找单条报告，返回 (report, index) 或 (None, -1)。"""
    data = get_report()
    for i, r in enumerate(data.get("reports", [])):
        if r.get("rid") == rid:
            return r, i
    return None, -1


def update_report(rid, mutator):
    """按 rid 原子更新单条报告。

    mutator(report) 返回非空字符串表示拒绝修改（在持文件锁状态下做的
    二次校验，避免「先查后改」并发下申诉与复核互相覆盖）。
    返回 (updated_report|None, error_message|None)。
    """
    result = {}

    def _upd(d):
        if d is None:
            return d
        reports = _backfill(d.get("reports", []))
        for r in reports:
            if r.get("rid") == rid:
                result["r"] = r
                result["err"] = mutator(r)
                break
        d["reports"] = reports
        if "r" in result and not result.get("err"):
            d["updated_at"] = now_iso()
        return d

    locked_update(REPORT_FILE, _upd, default=None)
    if result.get("err"):
        return None, result["err"]
    return result.get("r"), None


def user_flags(user_id):
    """统计某用户作为被标记方（a 侧）的报告数量。

    只统计 a 侧：检测是以「新提交」为主体触发的，被标记的是该提交者。
    返回 {"total": 全部标记, "pending": 待申诉, "appealed": 待复核,
          "upheld": 维持原判, "revoked": 已撤销}。
    """
    counts = {"total": 0, "pending": 0, "appealed": 0, "upheld": 0, "revoked": 0}
    for r in get_report().get("reports", []):
        if (r.get("a") or {}).get("user_id") != user_id:
            continue
        counts["total"] += 1
        status = r.get("status", "open")
        if status in ("upheld", "revoked"):
            counts[status] += 1
        elif (r.get("appeal") or {}).get("content"):
            counts["appealed"] += 1
        else:
            counts["pending"] += 1
    return counts


# ---- 申诉流程（不触碰检测判定） ----
APPEAL_MAX_LEN = 2000
REVIEW_NOTE_MAX_LEN = 1000


def submit_appeal(rid, user_id, content):
    """用户提交/修改申诉说明。已复核的报告不再接受申诉。"""
    content = (content or "").strip()
    if not content:
        return None, "申诉说明不能为空"
    if len(content) > APPEAL_MAX_LEN:
        return None, f"申诉说明不能超过 {APPEAL_MAX_LEN} 字"
    report, _ = find_report(rid)
    if report is None:
        return None, "申诉报告不存在"
    if (report.get("a") or {}).get("user_id") != user_id:
        return None, "只能对自己的作弊标记提交申诉"
    if report.get("status") in ("upheld", "revoked"):
        return None, "该报告已复核完成，不能再修改申诉"

    now = now_iso()
    first_at = (report.get("appeal") or {}).get("first_submitted_at") or now

    def _mutate(r):
        # 持锁二次校验：防止与管理员复核并发时覆盖结论
        if r.get("status") in ("upheld", "revoked"):
            return "该报告已复核完成，不能再修改申诉"
        r["appeal"] = {"content": content, "submitted_at": now,
                       "first_submitted_at": first_at}
        r["status"] = "open"
        return None

    return update_report(rid, _mutate)


def review_appeal(rid, admin, decision, note=""):
    """管理员复核申诉：decision=upheld 维持原判 / revoked 撤销标记。"""
    if decision not in ("upheld", "revoked"):
        return None, "无效的复核结论"
    report, _ = find_report(rid)
    if report is None:
        return None, "申诉报告不存在"
    if not (report.get("appeal") or {}).get("content"):
        return None, "用户尚未提交申诉"
    if report.get("status") in ("upheld", "revoked"):
        return None, "该申诉已处理，不能重复处理"

    review = {
        "decision": decision,
        "note": note,
        "admin_id": admin.get("id", ""),
        "admin_name": admin.get("nickname") or admin.get("username", ""),
        "reviewed_at": now_iso(),
    }

    def _mutate(r):
        # 持锁二次校验：防止重复处理 / 处理空申诉
        if r.get("status") in ("upheld", "revoked"):
            return "该申诉已处理，不能重复处理"
        if not (r.get("appeal") or {}).get("content"):
            return "用户尚未提交申诉"
        r["status"] = decision
        r.setdefault("reviews", []).append(review)
        return None

    return update_report(rid, _mutate)


# ---- 代码对比（仅供详情展示，不参与防作弊判定） ----
_LINE_COMMENT_RE = re.compile(r"(#.*$|//.*$)", re.MULTILINE)
_WS_LINE_RE = re.compile(r"\s+")


def normalize_lines(code, language=""):
    """逐行「展示用」归一化：去掉行注释、折叠空白，保留行结构。

    与判定用的 normalize_code 相互独立：这里按行处理，仅用于把两份
    代码对齐并高亮相似之处，任何改动都不会影响相似度判定结果。
    """
    lines = (code or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out = []
    for ln in lines:
        ln = _LINE_COMMENT_RE.sub("", ln)
        ln = _WS_LINE_RE.sub(" ", ln).strip()
        out.append(ln)
    return out


def build_diff(code_a, code_b, language_a="", language_b=""):
    """构建两份代码的行级对比，供管理员/用户查看相似之处。

    返回：
      {
        "rows": [{type, a:{no,text,norm}, b:{no,text,norm}}, ...],
        "unified": "统一 diff 文本",
        "stats": {"equal": n, "replace": n, "delete": n, "insert": n,
                  "matched_lines": n, "total_lines": n, "line_match_ratio": x.x}
      }
    type: equal 完全一致 / replace 结构相近(改动量小) /
          delete 仅 A 有 / insert 仅 B 有。
    """
    raw_a = (code_a or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    raw_b = (code_b or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    norm_a = normalize_lines(code_a, language_a)
    norm_b = normalize_lines(code_b, language_b)

    matcher = difflib.SequenceMatcher(a=norm_a, b=norm_b, autojunk=False)
    rows = []
    stats = {"equal": 0, "replace": 0, "delete": 0, "insert": 0,
             "matched_lines": 0,
             "total_a": len([x for x in norm_a if x]),
             "total_b": len([x for x in norm_b if x])}
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            stats["equal"] += i2 - i1
            for k in range(i2 - i1):
                if norm_a[i1 + k]:
                    stats["matched_lines"] += 1
                rows.append({"type": "equal",
                             "a": {"no": i1 + k + 1, "text": raw_a[i1 + k], "norm": norm_a[i1 + k]},
                             "b": {"no": j1 + k + 1, "text": raw_b[j1 + k], "norm": norm_b[j1 + k]}})
        elif tag == "replace":
            # 结构相近的行（归一化后高度相似）标记为 similar，帮助肉眼判断
            for k in range(max(i2 - i1, j2 - j1)):
                ai, bj = i1 + k, j1 + k
                av = norm_a[ai] if ai < i2 else None
                bv = norm_b[bj] if bj < j2 else None
                rtype = "replace"
                if av is not None and bv is not None:
                    ratio = difflib.SequenceMatcher(None, av, bv, autojunk=False).ratio()
                    if ratio >= 0.5:
                        rtype = "similar"
                rows.append({
                    "type": rtype,
                    "a": {"no": ai + 1, "text": raw_a[ai], "norm": av} if av is not None else None,
                    "b": {"no": bj + 1, "text": raw_b[bj], "norm": bv} if bv is not None else None,
                })
            stats["replace"] += max(i2 - i1, j2 - j1)
            # 相近行也计入「匹配行数」
            for ai, bj in zip(range(i1, i2), range(j1, j2)):
                if difflib.SequenceMatcher(None, norm_a[ai], norm_b[bj],
                                           autojunk=False).ratio() >= 0.5:
                    stats["matched_lines"] += 1
        elif tag == "delete":
            stats["delete"] += i2 - i1
            for ai in range(i1, i2):
                rows.append({"type": "delete",
                             "a": {"no": ai + 1, "text": raw_a[ai], "norm": norm_a[ai]},
                             "b": None})
        else:  # insert
            stats["insert"] += j2 - j1
            for bj in range(j1, j2):
                rows.append({"type": "insert", "a": None,
                             "b": {"no": bj + 1, "text": raw_b[bj], "norm": norm_b[bj]}})

    unified = "\n".join(difflib.unified_diff(
        raw_a, raw_b, fromfile="A", tofile="B", lineterm="", n=3))

    total = max(stats["total_a"], stats["total_b"], 0)
    stats["total_lines"] = total
    stats["line_match_ratio"] = round(stats["matched_lines"] / total, 4) if total else 0.0
    return {"rows": rows, "unified": unified, "stats": stats}


def sha1_code(code):
    return hashlib.sha1((code or "").encode("utf-8", "replace")).hexdigest()
