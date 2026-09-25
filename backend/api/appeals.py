"""防作弊报告详情与申诉 API。

角色划分：
  - 管理员：列出全部报告（支持按状态过滤）、查看含两份代码对比的详情、
    处理申诉（维持原判 / 撤销）；
  - 普通用户：只列出与自己相关的报告，查看自己一方的详情（含自己的代码，
    不含对方完整代码），提交/更新申诉说明。

所有写操作只作用于 data/settings/cheat_report.json 中的报告记录，
不会改动提交分数、评测状态或排行榜——防作弊判定本身保持独立。
"""
from flask import Blueprint, request

from backend.api import ok, err, require_auth, require_admin
from backend.judge import cheat, cheat_diff
from backend.judge.cheat import normalize_code
from backend.judge import engine

appeals_bp = Blueprint("appeals", __name__)


def _load_submissions(entry):
    """取报告双方提交的完整记录（含代码）；缺失的一方返回 None。"""
    subs = {}
    for side in ("a", "b"):
        rec = entry.get(side) or {}
        sub_id = rec.get("id")
        subs[side] = engine.get_submission(sub_id, include_code=True) if sub_id else None
    return subs


def _appeal_view(entry, side):
    """取某一方的申诉（视图层便捷字段）。"""
    return (cheat._appeals(entry) or {}).get(side)


def _base_view(entry):
    """报告的列表/通用字段（不含代码）。"""
    return {
        "report_id": entry.get("report_id"),
        "similarity": entry.get("similarity"),
        "status": entry.get("status", cheat.STATUS_OPEN),
        "reported_at": entry.get("reported_at") or cheat._entry_time(entry),
        "a": entry.get("a"),
        "b": entry.get("b"),
        "has_appeal": bool(cheat._appeals(entry)),
        "appeals": list(cheat._appeals(entry).values()),
        "resolution": entry.get("resolution"),
    }


# ---- 管理员 ----

@appeals_bp.get("/cheat/reports")
@require_admin
def admin_list_reports():
    status = request.args.get("status") or "all"
    reports = cheat.get_report().get("reports", [])
    if status in (cheat.STATUS_OPEN, cheat.STATUS_UPHELD, cheat.STATUS_REVOKED, "appealed"):
        if status == "appealed":
            reports = [r for r in reports if cheat._appeals(r)]
        else:
            reports = [r for r in reports if r.get("status", cheat.STATUS_OPEN) == status]
    items = [_base_view(r) for r in reports]
    return ok({
        "total": len(items),
        "pending_count": cheat.pending_count(),
        "items": items,
    })


@appeals_bp.get("/cheat/reports/<report_id>")
@require_admin
def admin_report_detail(report_id):
    entry = cheat.find_entry(report_id)
    if entry is None:
        return err("报告不存在", 404, 404)
    subs = _load_submissions(entry)
    code_a = (subs["a"] or {}).get("code", "")
    code_b = (subs["b"] or {}).get("code", "")
    detail = _base_view(entry)
    detail["diff"] = cheat_diff.build_diff(code_a, code_b, entry.get("similarity"))
    # 归一化后的两份代码：改变量名/加注释的抄袭在这里会完全一致
    detail["normalized"] = {
        "a": cheat.normalize_code(code_a),
        "b": cheat.normalize_code(code_b),
    }
    detail["submissions"] = {
        side: ({
            "id": s.get("id"),
            "language": s.get("language"),
            "status": s.get("status"),
            "score": s.get("score"),
            "created_at": s.get("created_at"),
            "code": s.get("code", ""),
            "code_missing": not bool(s.get("code")),
        } if s else {"id": (entry.get(side) or {}).get("id"), "code_missing": True})
        for side, s in subs.items()
    }
    return ok(detail)


@appeals_bp.post("/cheat/reports/<report_id>/resolve")
@require_admin
def admin_resolve(report_id):
    data = request.get_json(silent=True) or {}
    decision = data.get("decision")
    note = data.get("note") or ""
    updated, error = cheat.resolve_appeal(report_id, decision, request.user, note)
    if error:
        return err(error, 400)
    return ok(_base_view(updated))


# ---- 通知徽标 ----

@appeals_bp.get("/cheat/notifications")
@require_auth
def notifications():
    """导航栏徽标数据：管理员看待处理申诉数；用户看自己未申诉的标记数。"""
    if request.user.get("role") == "admin":
        return ok({"pending": cheat.pending_count(), "flagged": 0})
    uid = request.user["id"]
    flagged = 0
    pending = 0
    for r in cheat.list_for_user(uid):
        side = cheat._side_of(r, uid)
        mine = _appeal_view(r, side)
        if not mine:
            flagged += 1
        elif r.get("status") == cheat.STATUS_OPEN:
            pending += 1
    return ok({"pending": pending, "flagged": flagged})


# ---- 被标记用户 ----

@appeals_bp.get("/cheat/my-reports")
@require_auth
def my_reports():
    uid = request.user["id"]
    items = []
    for r in cheat.list_for_user(uid):
        view = _base_view(r)
        side = cheat._side_of(r, uid)
        view["my_side"] = side
        view["my_appeal"] = _appeal_view(r, side)
        # 列表不暴露对方申诉全文以外的隐私；对方用户名本来就在报告里
        items.append(view)
    pending = sum(1 for v in items
                  if v["my_appeal"] and v["status"] == cheat.STATUS_OPEN)
    unresolved = sum(1 for v in items if not v["my_appeal"])
    return ok({"total": len(items), "pending": pending,
               "unresolved": unresolved, "items": items})


@appeals_bp.get("/cheat/my-reports/<report_id>")
@require_auth
def my_report_detail(report_id):
    uid = request.user["id"]
    entry = cheat.find_entry(report_id)
    if entry is None:
        return err("报告不存在", 404, 404)
    side = cheat._side_of(entry, uid)
    if side is None and request.user.get("role") != "admin":
        return err("无权查看该报告", 403, 403)
    subs = _load_submissions(entry)
    my_sub = subs[side] if side else None
    other_side = "b" if side == "a" else "a"
    other_sub = subs.get(other_side)
    # 用户只能拿到自己的完整代码；对方仅展示对比所需的最小信息
    other_rec = entry.get(other_side) or {}
    view = _base_view(entry)
    view["my_side"] = side
    view["my_appeal"] = _appeal_view(entry, side) if side else None
    view["my_submission"] = ({
        "id": my_sub.get("id"),
        "language": my_sub.get("language"),
        "code": my_sub.get("code", ""),
    } if my_sub else None)
    view["other"] = {
        "username": other_rec.get("username", ""),
        "submission_id": other_rec.get("id", ""),
        "language": (other_sub or {}).get("language", ""),
        "line_count": len((other_sub or {}).get("code", "").splitlines()),
    }
    # 雷同片段只给行号与来自「自己代码」的预览（matched_blocks.preview
    # 只取自第一份代码，即自己的代码），不泄露对方源码
    my_code = (my_sub or {}).get("code", "")
    other_code = (other_sub or {}).get("code", "")
    view["matched_blocks"] = cheat_diff.matched_blocks(my_code, other_code)
    view["similarity_detail"] = cheat_diff.build_diff(
        my_code, my_code, entry.get("similarity")
    )["similarity"]
    return ok(view)


@appeals_bp.post("/cheat/my-reports/<report_id>/appeal")
@require_auth
def submit_appeal(report_id):
    data = request.get_json(silent=True) or {}
    updated, error = cheat.submit_appeal(
        report_id, request.user["id"], data.get("text") or ""
    )
    if error:
        return err(error, 400)
    side = cheat._side_of(updated, request.user["id"])
    view = _base_view(updated)
    view["my_side"] = side
    view["my_appeal"] = _appeal_view(updated, side)
    return ok(view)
