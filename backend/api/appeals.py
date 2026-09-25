"""作弊报告与申诉 API。

角色划分：
  - 普通用户：只能查看「自己作为被标记方（a 侧）」的报告摘要、
    在自己的报告详情中看到己方代码与相似行位置、提交/修改申诉说明；
  - 管理员：可查看全部报告，详情中含双方代码与逐行对比，并可对
    已提交的申诉做复核（维持原判 upheld / 撤销标记 revoked）。

本模块只读写 cheat_report.json 中的申诉字段，不改变防作弊检测
（normalize_code / detect_similarity）与提交分片上的判定结果。
"""
import os

from flask import Blueprint, request

from backend import config
from backend.api import ok, err, require_auth, require_admin
from backend.storage import read_json
from backend.judge import cheat, engine

appeals_bp = Blueprint("appeals", __name__)


def _problem_title(problem_id):
    p = read_json(os.path.join(config.PROBLEMS_DIR, f"{problem_id}.json"))
    return (p or {}).get("title", "") if p else ""


def _appeal_state(report):
    """报告的展示状态：pending 待申诉 / appealed 待复核 /
    upheld 维持原判 / revoked 已撤销。"""
    status = report.get("status", "open")
    if status in ("upheld", "revoked"):
        return status
    if (report.get("appeal") or {}).get("content"):
        return "appealed"
    return "pending"


def _base(report, include_title=False):
    """列表/详情共用的报告元数据（不含代码）。"""
    a, b = report.get("a") or {}, report.get("b") or {}
    item = {
        "rid": report.get("rid"),
        "similarity": report.get("similarity"),
        "state": _appeal_state(report),
        "status": report.get("status", "open"),
        "detected_at": report.get("detected_at") or a.get("created_at", ""),
        "problem_id": a.get("problem_id", ""),
        "appeal": report.get("appeal"),
        "reviews": report.get("reviews", []),
        "a": {
            "submission_id": a.get("id", ""),
            "user_id": a.get("user_id", ""),
            "username": a.get("username", ""),
            "language": a.get("language", ""),
            "created_at": a.get("created_at", ""),
        },
        "b": {
            "submission_id": b.get("id", ""),
            "user_id": b.get("user_id", ""),
            "username": b.get("username", ""),
            "language": b.get("language", ""),
            "created_at": b.get("created_at", ""),
        },
    }
    if include_title:
        item["problem_title"] = _problem_title(item["problem_id"])
    return item


def _redact_side(diff, side):
    """用户侧详情：抹掉对方代码，只保留行号与匹配类型。"""
    other = "b" if side == "a" else "a"
    for row in diff.get("rows", []):
        cell = row.get(other)
        if cell:
            row[other] = {"no": cell.get("no")}
    diff.pop("unified", None)
    return diff


def _build_detail(report, viewer):
    """组装报告详情。管理员可看双方代码与对比；被标记用户只看己方侧。"""
    is_admin = viewer.get("role") == "admin"
    a, b = report.get("a") or {}, report.get("b") or {}
    detail = _base(report, include_title=True)

    sub_a = engine.get_submission(a.get("id"), include_code=True) if a.get("id") else None
    sub_b = engine.get_submission(b.get("id"), include_code=True) if b.get("id") else None
    code_a = (sub_a or {}).get("code", "")
    code_b = (sub_b or {}).get("code", "")
    detail["a"]["submission_exists"] = sub_a is not None
    detail["b"]["submission_exists"] = sub_b is not None

    diff = cheat.build_diff(code_a, code_b,
                            a.get("language", ""), b.get("language", ""))
    if is_admin:
        detail["a"]["code"] = code_a
        detail["b"]["code"] = code_b
        detail["diff"] = diff
    else:
        # 仅被标记方（a 侧）本人可访问；对方身份与代码均不返回
        detail["b"] = {"submission_exists": sub_b is not None}
        detail["diff"] = _redact_side(diff, "a")
    return detail


# ---- 被标记用户 ----
@appeals_bp.get("/cheat-reports/my")
@require_auth
def my_reports():
    uid = request.user["id"]
    reports = cheat.get_report().get("reports", [])
    mine = [r for r in reports if (r.get("a") or {}).get("user_id") == uid]
    items = [_base(r, include_title=True) for r in mine]
    return ok({"total": len(items), "items": items,
               "flags": cheat.user_flags(uid)})


@appeals_bp.get("/cheat-reports/my/<rid>")
@require_auth
def my_report_detail(rid):
    report, _ = cheat.find_report(rid)
    if report is None:
        return err("报告不存在", 404, 404)
    if (report.get("a") or {}).get("user_id") != request.user["id"]:
        return err("无权查看该报告", 403, 403)
    return ok(_build_detail(report, request.user))


@appeals_bp.post("/cheat-reports/my/<rid>/appeal")
@require_auth
def submit_appeal(rid):
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return err("申诉说明不能为空", 400)
    if len(content) > cheat.APPEAL_MAX_LEN:
        return err(f"申诉说明不能超过 {cheat.APPEAL_MAX_LEN} 字", 400)
    updated, msg = cheat.submit_appeal(rid, request.user["id"], content)
    if updated is None:
        status = 403 if "只能" in msg else 404
        if "已复核" in msg:
            status = 400
        return err(msg, status, status)
    return ok(_base(updated, include_title=True))


# ---- 管理员 ----
@appeals_bp.get("/cheat-reports")
@require_admin
def list_reports():
    state = request.args.get("state")
    reports = cheat.get_report().get("reports", [])
    if state:
        reports = [r for r in reports if _appeal_state(r) == state]
    items = []
    for r in reports:
        item = _base(r)
        item["problem_title"] = _problem_title(item["problem_id"])
        items.append(item)
    return ok({"total": len(items), "items": items})


@appeals_bp.get("/cheat-reports/<rid>")
@require_admin
def report_detail(rid):
    report, _ = cheat.find_report(rid)
    if report is None:
        return err("报告不存在", 404, 404)
    return ok(_build_detail(report, request.user))


@appeals_bp.post("/cheat-reports/<rid>/decision")
@require_admin
def review(rid):
    data = request.get_json(silent=True) or {}
    decision = (data.get("decision") or "").strip()
    note = (data.get("note") or "").strip()
    if len(note) > cheat.REVIEW_NOTE_MAX_LEN:
        return err(f"复核备注不能超过 {cheat.REVIEW_NOTE_MAX_LEN} 字", 400)
    updated, msg = cheat.review_appeal(rid, request.user, decision, note)
    if updated is None:
        return err(msg, 400, 400)
    return ok(_base(updated, include_title=True))
