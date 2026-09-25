"""防作弊检测。

主要手段：
  1. 代码相似度检测：对源码做归一化（去注释、去空白、统一标识符）后计算
     SimHash 指纹，再对相近指纹做精确相似度（汉明距离）聚类；
  2. 时间窗检测：同一题目在短时间内出现高度相似提交则标记；
  3. 完全一致检测：直接哈希比对，捕获原样抄袭。

检测结果写入 data/settings/cheat_report.json，并可在提交记录中标记。
"""
import hashlib
import os
import re

from backend import config
from backend.storage import read_json, locked_update
from backend.utils import now_iso, gen_id, truncate

REPORT_FILE = os.path.join(config.SETTINGS_DIR, "cheat_report.json")

# 报告处理状态
#   open     待处理：尚无申诉，或用户已申诉、等待管理员处理
#   upheld   维持原判：管理员复核后确认作弊标记
#   revoked  撤销：管理员复核后撤销作弊标记
STATUS_OPEN = "open"
STATUS_UPHELD = "upheld"
STATUS_REVOKED = "revoked"
RESOLVED_STATUSES = (STATUS_UPHELD, STATUS_REVOKED)
MAX_REPORTS = 500

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


def _record_for(pair):
    # 引擎传入的是单条提交 dict（兼容历史的二元组调用方式）
    a = pair[0] if isinstance(pair, (list, tuple)) else pair
    return {
        "id": a["id"],
        "user_id": a["user_id"],
        "username": a.get("username", ""),
        "problem_id": a.get("problem_id", ""),
        "created_at": a.get("created_at", ""),
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
    """把一次疑似作弊对写入报告文件。

    注意：本函数只负责「记录检测结果」，与申诉流程完全独立，
    申诉字段（appeal/status）由其余辅助函数维护。
    """
    # 每条报告一个稳定 ID（供申诉 / 处理接口定位）
    entry.setdefault("report_id", gen_id("cr"))
    entry.setdefault("reported_at", now_iso())
    entry.setdefault("status", STATUS_OPEN)

    def _upd(d):
        if d is None:
            d = {"reports": [], "updated_at": ""}
        d.setdefault("reports", [])
        # 兼容旧数据：为没有 report_id 的历史记录补 ID 与默认状态
        for r in d["reports"]:
            if not r.get("report_id"):
                r["report_id"] = gen_id("cr")
            r.setdefault("status", STATUS_OPEN)
        d["reports"].insert(0, entry)
        d["reports"] = _trim_reports(d["reports"])
        d["updated_at"] = now_iso()
        return d
    locked_update(REPORT_FILE, _upd, default=None)


def _trim_reports(reports):
    """控制报告数量：优先丢弃没有申诉的最旧记录，绝不丢已申诉的。"""
    if len(reports) <= MAX_REPORTS:
        return reports
    keep = [r for r in reports if _has_appeal(r)]
    rest = [r for r in reports if not _has_appeal(r)]
    spare = MAX_REPORTS - len(keep)
    if spare > 0:
        keep.extend(rest[:spare])
    keep.sort(key=lambda r: r.get("reported_at") or _entry_time(r), reverse=True)
    return keep[:MAX_REPORTS]


def get_report():
    """读取防作弊报告（顺带为旧数据补齐 ID/状态字段，保证视图一致）。"""
    d = read_json(REPORT_FILE, {"reports": [], "updated_at": ""})
    if d is None:
        d = {"reports": [], "updated_at": ""}
    for r in d.setdefault("reports", []):
        if not r.get("report_id"):
            r["report_id"] = gen_id("cr")
        r.setdefault("status", STATUS_OPEN)
    return d


def _entry_time(entry):
    a = entry.get("a") or {}
    return a.get("created_at") or ""


def _side_of(entry, user_id):
    """用户在报告中属于哪一方：'a' / 'b' / None（与报告无关）。"""
    a, b = entry.get("a") or {}, entry.get("b") or {}
    if a.get("user_id") == user_id:
        return "a"
    if b.get("user_id") == user_id:
        return "b"
    return None


def _appeals(entry):
    """返回报告的申诉映射 {side: appeal}，兼容历史单 appeal 字段。"""
    appeals = entry.get("appeals")
    if isinstance(appeals, dict):
        return appeals
    # 旧版本可能写过单个 appeal 对象：迁移到 a 方
    legacy = entry.get("appeal")
    if isinstance(legacy, dict) and legacy.get("user_id"):
        side = _side_of(entry, legacy.get("user_id")) or "a"
        return {side: legacy}
    return {}


def _has_appeal(entry):
    return bool(_appeals(entry))


def _entry_identity(entry):
    """返回报告涉及的两个用户 id。"""
    a = entry.get("a") or {}
    b = entry.get("b") or {}
    return a.get("user_id"), b.get("user_id")


def find_entry(report_id):
    """按 report_id 取单条报告。"""
    if not report_id:
        return None
    for r in get_report().get("reports", []):
        if r.get("report_id") == report_id:
            return r
    return None


def list_for_user(user_id):
    """返回与某用户相关的全部报告。"""
    return [r for r in get_report().get("reports", [])
            if user_id in _entry_identity(r)]


def _mutate_entry(report_id, fn):
    """在文件锁内对单条报告做读-改-写。fn(entry)->None，返回更新后的条目。"""
    found = {}

    def _upd(d):
        if d is None:
            d = {"reports": [], "updated_at": ""}
        for r in d.setdefault("reports", []):
            if r.get("report_id") == report_id:
                fn(r)
                found["r"] = r
                break
        d["updated_at"] = now_iso()
        return d

    locked_update(REPORT_FILE, _upd, default=None)
    return found.get("r")


def submit_appeal(report_id, user_id, text):
    """被标记用户提交/更新自己一方的申诉说明。

    返回 (entry, error)：成功时 error 为 None。
    报告处理完毕（维持/撤销）后不允许再改申诉。
    """
    text = truncate((text or "").strip(), 2000)
    if not text:
        return None, "申诉说明不能为空"
    entry = find_entry(report_id)
    if entry is None:
        return None, "报告不存在"
    side = _side_of(entry, user_id)
    if side is None:
        return None, "无权对该报告申诉"
    if entry.get("status") in RESOLVED_STATUSES:
        return None, "该申诉已处理，无法修改"

    is_update = side in _appeals(entry)

    def _fn(r):
        r["status"] = STATUS_OPEN
        appeals = _appeals(r)
        appeals[side] = {
            "side": side,
            "text": text,
            "user_id": user_id,
            "submitted_at": now_iso(),
        }
        r["appeals"] = appeals
        r.pop("appeal", None)
    updated = _mutate_entry(report_id, _fn)
    return updated, ("申诉已更新" if is_update else None)


def resolve_appeal(report_id, decision, admin, note=""):
    """管理员对一份报告的申诉做最终处理。

    decision: STATUS_UPHELD（维持原判）/ STATUS_REVOKED（撤销）。
    返回 (entry, error)。只改报告展示状态，不触碰检测结果、提交分数与排名。
    """
    if decision not in RESOLVED_STATUSES:
        return None, "无效的处理决定"
    entry = find_entry(report_id)
    if entry is None:
        return None, "报告不存在"
    if not _appeals(entry):
        return None, "该报告尚无申诉，无需处理"
    if entry.get("status") in RESOLVED_STATUSES:
        return None, "该申诉已处理"
    note = truncate((note or "").strip(), 1000)

    def _fn(r):
        r["status"] = decision
        r["resolution"] = {
            "decision": decision,
            "note": note,
            "resolved_at": now_iso(),
            "resolved_by": (admin or {}).get("id", ""),
            "resolved_by_name": (admin or {}).get("username", ""),
        }
    return _mutate_entry(report_id, _fn), None


def pending_count():
    """统计待管理员处理的报告数（有申诉且未处理）。"""
    return sum(1 for r in get_report().get("reports", [])
               if _appeals(r) and r.get("status") == STATUS_OPEN)


def sha1_code(code):
    return hashlib.sha1((code or "").encode("utf-8", "replace")).hexdigest()
