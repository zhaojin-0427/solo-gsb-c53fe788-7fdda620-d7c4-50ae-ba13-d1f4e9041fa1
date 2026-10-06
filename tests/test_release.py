"""契约发布放行裁决（release gate）API 与裁决逻辑测试。

覆盖需求要点：
* 页面/API 可为指定 finding 登记理由 + UTC 到期时间的例外；
* 查询逐项依据及「阻断 / 待核 / 可放行」结果；
* 裁决读取**完整 findings**，不使用端点汇总、筛选结果或反例自检待定状态；
* 例外按报告版本指纹绑定——同分析 ID 重算后旧许可不沿用；finding 消失、
  例外过期均失效；未知 finding ID 拒绝；
* 原报告与覆盖不被登记动作修改。
"""
import io
import os
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


def _zip_bytes(folder: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(folder):
            for fn in files:
                full = os.path.join(root, fn)
                z.write(full, os.path.relpath(full, folder))
    return buf.getvalue()


@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def analysis_id(client):
    r = client.post(
        "/api/analyses",
        files={
            "baseline": ("b.zip", _zip_bytes("examples/baseline"),
                         "application/zip"),
            "candidate": ("c.zip", _zip_bytes("examples/candidate"),
                          "application/zip"),
        })
    assert r.status_code == 201, r.text
    return r.json()["analysis_id"]


def _findings(client, analysis_id):
    return client.get(f"/api/analyses/{analysis_id}").json()["findings"]


def _by_severity(findings, severity):
    return [f for f in findings if f["severity"] == severity]


def _future(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# --------------------------------------------------------------- 基础裁决
def test_decision_starts_blocked_when_breaking_exist(client, analysis_id):
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    findings = _findings(client, analysis_id)
    assert d["verdict"] in ("blocked", "needs_review")
    if any(f["severity"] == "breaking" for f in findings):
        assert d["verdict"] == "blocked"
    assert d["report_version"]
    assert len(d["items"]) == len(findings)
    assert {i["disposition"] for i in d["items"]} <= {
        "blocked", "needs_review", "releasable"}
    # 每项都带依据说明
    assert all(i["basis"] for i in d["items"])


def test_items_reference_full_findings_not_endpoint_summary(
        client, analysis_id):
    """逐项条目数等于完整 findings 数，而非端点数或筛选后数量。"""
    report = client.get(f"/api/analyses/{analysis_id}").json()
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    assert len(d["items"]) == report["summary"]["total_findings"]
    assert len(d["items"]) > report["summary"]["endpoints_total"]


def test_pending_self_check_does_not_drive_verdict(client, analysis_id):
    """反例自检为 pending 的 finding 仍按自身 severity 参与裁决。"""
    findings = _findings(client, analysis_id)
    pending = [f for f in findings
               if (f.get("witness") or {}).get("self_check", {})
               .get("baseline_state") == "pending"
               or (f.get("witness") or {}).get("candidate_state") == "pending"]
    if not pending:
        pytest.skip("示例中没有 pending 自检的 finding")
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    items = {i["finding_id"]: i for i in d["items"]}
    for f in pending:
        it = items[f["id"]]
        if f["severity"] == "breaking":
            assert it["disposition"] == "blocked"
        elif f["severity"] == "undetermined":
            assert it["disposition"] == "needs_review"


# --------------------------------------------------------------- 登记校验
def test_register_unknown_finding_rejected(client, analysis_id):
    r = client.put(
        f"/api/analyses/{analysis_id}/findings/nope-deadbeef/exception",
        json={"reason": "x", "expires_at": _future()})
    assert r.status_code == 404


def test_register_requires_reason(client, analysis_id):
    fid = _by_severity(_findings(client, analysis_id), "breaking")[0]["id"]
    r = client.put(
        f"/api/analyses/{analysis_id}/findings/{fid}/exception",
        json={"expires_at": _future()})
    assert r.status_code == 400


def test_register_rejects_naive_datetime(client, analysis_id):
    fid = _by_severity(_findings(client, analysis_id), "breaking")[0]["id"]
    r = client.put(
        f"/api/analyses/{analysis_id}/findings/{fid}/exception",
        json={"reason": "r", "expires_at": "2027-01-01T00:00:00"})
    assert r.status_code == 400
    assert "时区" in r.json()["detail"]


def test_register_rejects_past_expiry(client, analysis_id):
    fid = _by_severity(_findings(client, analysis_id), "breaking")[0]["id"]
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    r = client.put(
        f"/api/analyses/{analysis_id}/findings/{fid}/exception",
        json={"reason": "r", "expires_at": past})
    assert r.status_code == 400


def test_register_rejects_bad_datetime(client, analysis_id):
    fid = _by_severity(_findings(client, analysis_id), "breaking")[0]["id"]
    r = client.put(
        f"/api/analyses/{analysis_id}/findings/{fid}/exception",
        json={"reason": "r", "expires_at": "not-a-time"})
    assert r.status_code == 400


# --------------------------------------------------------------- 豁免→裁决
def test_except_all_blocking_moves_to_review(client, analysis_id):
    findings = _findings(client, analysis_id)
    breaking = _by_severity(findings, "breaking")
    assert breaking
    for f in breaking:
        r = client.put(
            f"/api/analyses/{analysis_id}/findings/{f['id']}/exception",
            json={"reason": f"豁免 {f['rule']}", "expires_at": _future(),
                  "created_by": "tester"})
        assert r.status_code == 200, r.text
        assert r.json()["exception_state"] == "active"
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    assert d["summary"]["remaining_breaking"] == 0
    assert d["summary"]["exceptions_excepted_breaking"] == len(breaking)
    if any(f["severity"] == "undetermined" for f in findings):
        assert d["verdict"] == "needs_review"
        assert d["verdict_label"] == "待核"
    else:
        assert d["verdict"] == "releasable"


def test_except_everything_releasable(client, analysis_id):
    findings = _findings(client, analysis_id)
    for f in findings:
        if f["severity"] in ("breaking", "undetermined"):
            r = client.put(
                f"/api/analyses/{analysis_id}/findings/{f['id']}/exception",
                json={"reason": "全部接受", "expires_at": _future(60)})
            assert r.status_code == 200, r.text
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    assert d["verdict"] == "releasable"
    assert d["verdict_label"] == "可放行"
    assert d["summary"]["remaining_breaking"] == 0
    assert d["summary"]["remaining_undetermined"] == 0


def test_excepted_item_shows_reason_and_active_basis(client, analysis_id):
    findings = _findings(client, analysis_id)
    target = _by_severity(findings, "breaking")[0]
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    item = next(i for i in d["items"] if i["finding_id"] == target["id"])
    assert item["effective"] is True
    assert item["exception"]["reason"]
    assert "例外生效" in item["basis"]


def test_register_is_upsert(client, analysis_id):
    """同 finding 重复登记更新理由/到期，不产生重复生效例外。"""
    from app.store import store
    findings = _findings(client, analysis_id)
    fid = _by_severity(findings, "breaking")[0]["id"]
    r1 = client.put(
        f"/api/analyses/{analysis_id}/findings/{fid}/exception",
        json={"reason": "第一次", "expires_at": _future(1)})
    assert r1.status_code == 200
    r2 = client.put(
        f"/api/analyses/{analysis_id}/findings/{fid}/exception",
        json={"reason": "第二次（更新）", "expires_at": _future(2)})
    assert r2.status_code == 200
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    item = next(i for i in d["items"] if i["finding_id"] == fid)
    assert item["exception"]["reason"] == "第二次（更新）"
    # 存储层同一三元组只有一条
    rows = [e for e in store.list_exceptions(analysis_id)
            if e["finding_id"] == fid]
    assert len(rows) == 1


def test_revoke_exception_restores_blocking(client, analysis_id):
    findings = _findings(client, analysis_id)
    target = _by_severity(findings, "breaking")[0]
    r = client.delete(
        f"/api/analyses/{analysis_id}/findings/{target['id']}/exception")
    assert r.status_code == 200, r.text
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    item = next(i for i in d["items"]
                if i["finding_id"] == target["id"])
    assert item["disposition"] == "blocked"
    assert item["exception"] is None
    # 再删一次 → 404
    r2 = client.delete(
        f"/api/analyses/{analysis_id}/findings/{target['id']}/exception")
    assert r2.status_code == 404


# --------------------------------------------------------------- 例外失效
def test_expired_exception_does_not_release(client, analysis_id,
                                            monkeypatch=None):
    """登记一个已到期例外：项保持阻断，且响应给出过期失效原因。"""
    from app.services import release as release_mod
    from app.store import store
    findings = _findings(client, analysis_id)
    target = _by_severity(findings, "breaking")[0]
    record = store.get(analysis_id)
    version = release_mod.report_version_of(record["report"])
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    store.upsert_exception(
        analysis_id, version, target["id"], "本应有效的理由",
        expires_at=past, created_by=None, now_ts=past)
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    item = next(i for i in d["items"] if i["finding_id"] == target["id"])
    assert item["disposition"] == "blocked"
    assert item["exception"] is None
    assert "已超过 UTC 到期时间" in item["basis"]
    stale = next(e for e in d["ineffective_exceptions"]
                 if e["finding_id"] == target["id"])
    assert stale["state"] == "expired"
    assert "到期" in stale["ineffective_reason"]
    # 清理，避免污染后续用例
    store.delete_exception(analysis_id, version, target["id"])


def test_report_recompute_invalidates_old_exceptions(client, analysis_id):
    """同分析 ID 覆盖报告后，旧版本例外不再生效（新结论不沿用旧许可）。"""
    from app.services import release as release_mod
    from app.store import store
    findings = _findings(client, analysis_id)
    target = _by_severity(findings, "breaking")[0]

    # 当前版本先登记例外并确认生效
    r = client.put(
        f"/api/analyses/{analysis_id}/findings/{target['id']}/exception",
        json={"reason": "旧版本许可", "expires_at": _future(30)})
    assert r.status_code == 200
    assert r.json()["exception_state"] == "active"

    # 模拟同 ID 重算：分析 ID 由文档包内容决定（不变），报告内容被覆盖，
    # 报告版本指纹随之变化。
    record = store.get(analysis_id)
    old_version = release_mod.report_version_of(record["report"])
    new_report = dict(record["report"])
    new_report["generated_by"] = (
        new_report.get("generated_by", "") + " [recomputed]")
    store.save(
        analysis_id=analysis_id,
        baseline_name=record["baseline_name"],
        candidate_name=record["candidate_name"],
        baseline_meta=new_report["packages"]["baseline"],
        candidate_meta=new_report["packages"]["candidate"],
        report_doc=new_report, stats=record["stats"],
        created_at=(datetime.now(timezone.utc) + timedelta(seconds=1))
        .isoformat(),
        packages=store.get_packages(analysis_id))
    new_version = release_mod.report_version_of(new_report)
    assert new_version != old_version

    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    assert d["report_version"] == new_version
    item = next(i for i in d["items"] if i["finding_id"] == target["id"])
    assert item["exception"] is None
    assert item["disposition"] == "blocked"
    stale = next(e for e in d["ineffective_exceptions"]
                 if e["finding_id"] == target["id"])
    assert stale["state"] == "stale_report_version"
    assert "报告已重新计算" in stale["ineffective_reason"]
    # 同 finding 在新版本上需要重新登记
    r2 = client.put(
        f"/api/analyses/{analysis_id}/findings/{target['id']}/exception",
        json={"reason": "新版本重新评审", "expires_at": _future(10)})
    assert r2.status_code == 200
    d2 = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    item2 = next(i for i in d2["items"]
                 if i["finding_id"] == target["id"])
    assert item2["exception"]["reason"] == "新版本重新评审"
    # 旧许可仍以失效身份列出
    assert any(e["state"] == "stale_report_version"
               for e in d2["ineffective_exceptions"])

    # 还原原始报告，避免污染后续测试
    store.save(
        analysis_id=analysis_id,
        baseline_name=record["baseline_name"],
        candidate_name=record["candidate_name"],
        baseline_meta=record["report"]["packages"]["baseline"],
        candidate_meta=record["report"]["packages"]["candidate"],
        report_doc=record["report"], stats=record["stats"],
        created_at=record["created_at"],
        packages=store.get_packages(analysis_id))


def test_exception_for_vanished_finding_is_orphan(client, analysis_id):
    """例外绑定的 finding 从新报告中消失 → 许可失效并列出原因。"""
    from app.services import release as release_mod
    from app.store import store
    findings = _findings(client, analysis_id)
    target = _by_severity(findings, "breaking")[0]
    record = store.get(analysis_id)
    old_version = release_mod.report_version_of(record["report"])
    future = datetime.now(timezone.utc) + timedelta(days=30)
    store.upsert_exception(
        analysis_id, old_version, target["id"], "finding 消失前的许可",
        expires_at=future, created_by=None,
        now_ts=datetime.now(timezone.utc))

    # 重算后的报告不再包含该 finding（模拟该结论消失），其余构造新指纹
    new_report = dict(record["report"])
    new_report["findings"] = [f for f in new_report["findings"]
                              if f["id"] != target["id"]]
    new_version = release_mod.report_version_of(new_report)
    assert new_version != old_version
    store.save(
        analysis_id=analysis_id,
        baseline_name=record["baseline_name"],
        candidate_name=record["candidate_name"],
        baseline_meta=record["report"]["packages"]["baseline"],
        candidate_meta=record["report"]["packages"]["candidate"],
        report_doc=new_report, stats=record["stats"],
        created_at=record["created_at"],
        packages=store.get_packages(analysis_id))

    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    assert all(i["finding_id"] != target["id"] for i in d["items"])
    stale = next(e for e in d["ineffective_exceptions"]
                 if e["finding_id"] == target["id"])
    # 版本先不匹配即标记 stale；直接用 decide 验证 finding 消失的分支
    assert stale["state"] == "stale_report_version"

    # 构造“版本一致但 finding 不存在”的孤立例外，验证 orphan 判定
    orphan = release_mod.decide(
        new_report,
        [{"finding_id": target["id"], "report_version": new_version,
          "reason": "x", "expires_at": future.isoformat(),
          "created_at": datetime.now(timezone.utc).isoformat()}])
    o = next(e for e in orphan["ineffective_exceptions"]
             if e["finding_id"] == target["id"])
    assert o["state"] == "finding_absent"
    assert "消失" in o["ineffective_reason"]

    # 还原
    store.save(
        analysis_id=analysis_id,
        baseline_name=record["baseline_name"],
        candidate_name=record["candidate_name"],
        baseline_meta=record["report"]["packages"]["baseline"],
        candidate_meta=record["report"]["packages"]["candidate"],
        report_doc=record["report"], stats=record["stats"],
        created_at=record["created_at"],
        packages=store.get_packages(analysis_id))


# --------------------------------------------------------------- 纯逻辑
def test_decide_verdict_ordering():
    from app.services.release import decide, BLOCKED, NEEDS_REVIEW, \
        RELEASABLE

    def mk_report(fids):
        return {"analysis_id": "a", "findings": [
            {"id": fid, "severity": sev, "rule": "R", "rule_title": "t",
             "endpoint": {"path": "/p", "method": "GET"}, "message": "m"}
            for fid, sev in fids]}

    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    rep = mk_report([("b1", "breaking"), ("u1", "undetermined")])
    assert decide(rep, [])["verdict"] == BLOCKED
    # 豁免破坏性 → 待核
    v = release_decide_with(rep, [("b1", future)])
    assert v["verdict"] == NEEDS_REVIEW
    assert v["summary"]["remaining_breaking"] == 0
    assert v["summary"]["remaining_undetermined"] == 1
    # 全部豁免 → 可放行
    v = release_decide_with(rep, [("b1", future), ("u1", future)])
    assert v["verdict"] == RELEASABLE
    # 只有无法判定 → 待核
    rep2 = mk_report([("u1", "undetermined"), ("c1", "compatible")])
    assert decide(rep2, [])["verdict"] == NEEDS_REVIEW
    # 只有兼容 → 可放行
    rep3 = mk_report([("c1", "compatible")])
    assert decide(rep3, [])["verdict"] == RELEASABLE


def release_decide_with(report, specs):
    from app.services.release import decide, report_version_of
    version = report_version_of(report)
    excs = [{"finding_id": fid, "report_version": version, "reason": "r",
             "expires_at": exp,
             "created_at": datetime.now(timezone.utc).isoformat()}
            for fid, exp in specs]
    return decide(report, excs)


def test_expired_vs_future_iso_handling():
    from app.services.release import decide, report_version_of
    rep = {"analysis_id": "a", "findings": [
        {"id": "b1", "severity": "breaking", "rule": "R",
         "rule_title": "t", "endpoint": {"path": "/p", "method": "GET"},
         "message": "m"}]}
    version = report_version_of(rep)
    base = {"finding_id": "b1", "report_version": version, "reason": "r",
            "created_at": datetime.now(timezone.utc).isoformat()}
    # 'Z' 后缀的未来时间生效
    ok = decide(rep, [{**base, "expires_at":
                       (datetime.now(timezone.utc)
                        + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}])
    assert ok["verdict"] == "releasable"
    # 过去时间失效
    bad = decide(rep, [{**base, "expires_at":
                        (datetime.now(timezone.utc) - timedelta(days=2))
                        .isoformat()}])
    assert bad["verdict"] == "blocked"
    assert bad["ineffective_exceptions"][0]["state"] == "expired"


# --------------------------------------------------------------- 隔离性
def test_exception_does_not_modify_report_or_export(client, analysis_id):
    before = client.get(f"/api/analyses/{analysis_id}").json()
    findings = _findings(client, analysis_id)
    fid = _by_severity(findings, "breaking")[0]["id"]
    exp1 = client.get(f"/api/analyses/{analysis_id}/export")
    client.put(
        f"/api/analyses/{analysis_id}/findings/{fid}/exception",
        json={"reason": "不得写入报告", "expires_at": _future()})
    after = client.get(f"/api/analyses/{analysis_id}").json()
    exp2 = client.get(f"/api/analyses/{analysis_id}/export")
    assert before["findings"] == after["findings"]
    assert exp1.content == exp2.content
    assert "exception" not in exp2.text


def test_decision_independent_of_export_filter(client, analysis_id):
    """严重度筛选导出不影响裁决（裁决始终读完整 findings）。"""
    filtered = client.get(
        f"/api/analyses/{analysis_id}/export?severity=compatible")
    assert filtered.status_code == 200
    d = client.get(f"/api/analyses/{analysis_id}/release-decision").json()
    full = client.get(f"/api/analyses/{analysis_id}").json()
    assert len(d["items"]) == full["summary"]["total_findings"]


def test_exception_endpoints_on_missing_analysis(client):
    r = client.get("/api/analyses/doesnotexist/release-decision")
    assert r.status_code == 404
    r = client.put(
        "/api/analyses/doesnotexist/findings/x/exception",
        json={"reason": "r", "expires_at": _future()})
    assert r.status_code == 404
