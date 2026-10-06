"""契约发布放行裁决（release gate）。

比对器把命中的规则逐条写入 ``report.findings``，再由 finding 严重度聚合出
端点严重度。发布裁决必须读取**完整的 findings**——端点汇总（端点可能同时含
多条 finding）、页面/导出的严重度筛选结果、以及反例自检的「待定」三态都不能
替代 finding 自身的严重度：

* 仍存在**破坏性** finding（且无生效例外）→ ``blocked``（阻断）；
* 否则仍存在**无法判定** finding（且无生效例外）→ ``needs_review``（待核）；
* 两者都没有 → ``releasable``（可放行）。

例外（exception）按 **(analysis_id, report_version, finding_id)** 三元组
绑定。``report_version`` 是当前完整报告的 SHA-256 指纹：分析 ID 只由文档包
内容计算，同 ID 重新上传会覆盖报告（例如引擎升级后结论变化），若只按分析 ID
关联，重算后的新结论会沿用旧许可——因此版本不匹配的旧许可一律不生效；
finding 在新报告中消失、或例外超过 UTC 到期时间同样不生效。
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from ..serialization import export_fingerprint

# 总体裁决
BLOCKED = "blocked"            # 剩余破坏性项 → 阻断
NEEDS_REVIEW = "needs_review"  # 仅剩无法判定项 → 待核
RELEASABLE = "releasable"      # 均无 → 可放行

VERDICT_LABELS = {
    BLOCKED: "阻断",
    NEEDS_REVIEW: "待核",
    RELEASABLE: "可放行",
}

# 单项处置
ITEM_BLOCKED = "blocked"
ITEM_NEEDS_REVIEW = "needs_review"
ITEM_RELEASABLE = "releasable"

# 例外状态
EX_ACTIVE = "active"                  # 生效中（版本匹配、finding 仍在、未过期）
EX_EXPIRED = "expired"                # 已超过 UTC 到期时间
EX_STALE = "stale_report_version"     # 绑定的是旧版本报告（报告已重算）
EX_ORPHAN = "finding_absent"          # 绑定的 finding 已从报告中消失

_BREAKING = "breaking"
_UNDETERMINED = "undetermined"
_COMPATIBLE = "compatible"


class ExceptionValidationError(ValueError):
    """登记例外时的参数错误（API 层映射为 400）。"""


def parse_expires_at(value: Any) -> datetime:
    """解析并校验例外到期时间。

    接受 ISO 8601 字符串（``2027-01-01T00:00:00Z`` / 带偏移量）或已有的
    ``datetime``。必须带时区信息（裁决统一使用 UTC），且必须晚于当前 UTC
    时间，否则抛出 :class:`ExceptionValidationError`。
    """
    now = datetime.now(timezone.utc)
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        # Python 3.11 的 fromisoformat 接受 "Z" 后缀；兼容显式替换。
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            raise ExceptionValidationError(
                "expires_at 不是合法的 ISO 8601 时间，"
                "例如 2027-01-01T00:00:00Z")
    else:
        raise ExceptionValidationError(
            "expires_at 必填，须为 ISO 8601 UTC 时间字符串")
    if dt.tzinfo is None:
        raise ExceptionValidationError(
            "expires_at 必须带时区偏移（UTC 请用 Z 或 +00:00），"
            "不接受无时区的本地时间")
    dt = dt.astimezone(timezone.utc)
    if dt <= now:
        raise ExceptionValidationError(
            f"expires_at（{dt.isoformat()}）必须晚于当前 UTC 时间"
            f"（{now.isoformat()}），例外不能登记为已到期")
    return dt


def report_version_of(report_doc: dict) -> str:
    """当前完整报告的版本指纹（与报告内容一一对应）。"""
    return export_fingerprint(report_doc)


def _exception_state(exc: dict, *, report_version: str,
                     current_finding_ids: set[str],
                     now: datetime) -> str:
    if exc.get("report_version") != report_version:
        return EX_STALE
    if exc.get("finding_id") not in current_finding_ids:
        return EX_ORPHAN
    expires = exc.get("expires_at")
    if isinstance(expires, str):
        try:
            exp_dt = datetime.fromisoformat(
                expires.replace("Z", "+00:00"))
        except ValueError:
            return EX_EXPIRED
        if exp_dt.tzinfo is not None:
            exp_dt = exp_dt.astimezone(timezone.utc)
        if exp_dt <= now:
            return EX_EXPIRED
    return EX_ACTIVE


_STATE_REASON = {
    EX_STALE: "例外绑定的报告版本已过期：分析 ID 相同但报告已重新计算"
              "（内容或引擎结论发生变化），旧许可不适用于新结论",
    EX_ORPHAN: "例外绑定的 finding 已从当前报告中消失，旧许可不再生效",
    EX_EXPIRED: "例外已超过 UTC 到期时间，许可失效",
}


def decide(report_doc: dict, exceptions: list[dict], *,
           now: Optional[datetime] = None) -> dict:
    """依据完整 findings 与登记的例外计算逐项依据与总体裁决。

    ``report_doc`` 必须是存储中的**完整、未筛选**报告；``exceptions`` 为该
    分析下所有历史例外（含旧版本绑定，用于在响应中说明失效原因）。
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc)
    findings = report_doc.get("findings") or []
    report_version = report_version_of(report_doc)
    finding_ids = {f["id"] for f in findings}

    # 当前版本、且 finding 仍存在的例外按 finding_id 索引（同 finding 以
    # 最新登记的一条为准——登记接口本身做 upsert）。
    current_exc: dict[str, dict] = {}
    ineffective: list[dict] = []
    for exc in exceptions:
        state = _exception_state(
            exc, report_version=report_version,
            current_finding_ids=finding_ids, now=now)
        fid = exc.get("finding_id")
        if state == EX_ACTIVE:
            prev = current_exc.get(fid)
            if prev is None or (exc.get("created_at") or "") >= \
                    (prev.get("created_at") or ""):
                current_exc[fid] = exc
            continue
        ineffective.append(_ineffective_view(exc, state))

    items: list[dict] = []
    remaining_breaking = 0
    remaining_undetermined = 0
    excepted_breaking = 0
    excepted_undetermined = 0
    expired_count = 0
    for f in findings:
        fid = f["id"]
        severity = f["severity"]
        exc = current_exc.get(fid)
        # 注意：过期/旧版本例外不能放进 current_exc；当前版本但已过期的
        # 例外要在该项上显式给出失效原因。
        expired_here = next((e for e in ineffective
                             if e["finding_id"] == fid
                             and e["state"] == EX_EXPIRED
                             and e.get("report_version") == report_version),
                            None)
        if expired_here:
            expired_count += 1

        ep = f.get("endpoint") or {}
        item: dict[str, Any] = {
            "finding_id": fid,
            "rule": f.get("rule"),
            "rule_title": f.get("rule_title"),
            "severity": severity,
            "endpoint": {"path": ep.get("path"),
                         "method": ep.get("method")},
            "message": f.get("message"),
            "exception": _exception_view(exc) if exc else None,
        }

        if exc is not None:
            item["exception_state"] = EX_ACTIVE
            item["effective"] = True
            item["disposition"] = ITEM_RELEASABLE
            item["basis"] = (
                f"例外生效：{exc.get('reason')}；UTC 到期 "
                f"{exc.get('expires_at')}（绑定报告版本 "
                f"{report_version[:12]}…）")
            if severity == _BREAKING:
                excepted_breaking += 1
            elif severity == _UNDETERMINED:
                excepted_undetermined += 1
        elif severity == _BREAKING:
            item["exception_state"] = None
            item["effective"] = False
            item["disposition"] = ITEM_BLOCKED
            if expired_here:
                item["basis"] = (
                    "破坏性 finding 无生效例外：原有例外已失效——"
                    + _STATE_REASON[EX_EXPIRED])
            else:
                item["basis"] = "破坏性 finding 未登记生效例外，阻断发布"
            remaining_breaking += 1
        elif severity == _UNDETERMINED:
            item["exception_state"] = None
            item["effective"] = False
            item["disposition"] = ITEM_NEEDS_REVIEW
            if expired_here:
                item["basis"] = (
                    "无法判定 finding 无生效例外：原有例外已失效——"
                    + _STATE_REASON[EX_EXPIRED])
            else:
                item["basis"] = "无法判定 finding 未登记生效例外，需人工待核"
            remaining_undetermined += 1
        else:
            item["exception_state"] = None
            item["effective"] = False
            item["disposition"] = ITEM_RELEASABLE
            item["basis"] = "兼容项，无需例外"
        items.append(item)

    if remaining_breaking:
        verdict = BLOCKED
    elif remaining_undetermined:
        verdict = NEEDS_REVIEW
    else:
        verdict = RELEASABLE

    return {
        "analysis_id": report_doc.get("analysis_id"),
        "report_version": report_version,
        "decided_at": now.isoformat(),
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict],
        "summary": {
            "findings_total": len(findings),
            "breaking_total": sum(1 for f in findings
                                  if f["severity"] == _BREAKING),
            "undetermined_total": sum(1 for f in findings
                                      if f["severity"] == _UNDETERMINED),
            "compatible_total": sum(1 for f in findings
                                    if f["severity"] == _COMPATIBLE),
            "remaining_breaking": remaining_breaking,
            "remaining_undetermined": remaining_undetermined,
            "exceptions_active": len(current_exc),
            "exceptions_excepted_breaking": excepted_breaking,
            "exceptions_excepted_undetermined": excepted_undetermined,
            "exceptions_expired": expired_count,
            "exceptions_stale_version": sum(
                1 for e in ineffective if e["state"] == EX_STALE),
            "exceptions_orphan": sum(
                1 for e in ineffective if e["state"] == EX_ORPHAN),
        },
        "items": items,
        "ineffective_exceptions": ineffective,
    }


def _exception_view(exc: dict) -> dict:
    return {
        "reason": exc.get("reason"),
        "expires_at": exc.get("expires_at"),
        "created_by": exc.get("created_by"),
        "created_at": exc.get("created_at"),
        "updated_at": exc.get("updated_at"),
    }


def _ineffective_view(exc: dict, state: str) -> dict:
    view = {
        "finding_id": exc.get("finding_id"),
        "report_version": exc.get("report_version"),
        "state": state,
        "state_label": {
            EX_STALE: "版本失效", EX_ORPHAN: "finding 消失",
            EX_EXPIRED: "已过期"}.get(state, state),
        "reason": exc.get("reason"),
        "expires_at": exc.get("expires_at"),
        "created_by": exc.get("created_by"),
        "created_at": exc.get("created_at"),
        "updated_at": exc.get("updated_at"),
        "ineffective_reason": _STATE_REASON[state],
    }
    return view
