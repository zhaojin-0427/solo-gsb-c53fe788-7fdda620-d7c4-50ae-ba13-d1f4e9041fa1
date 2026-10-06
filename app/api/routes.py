from fastapi import APIRouter, HTTPException, Request, UploadFile
from fastapi.responses import Response
from datetime import datetime, timezone

from ..analysis import analyze, filter_report, from_envelope
from ..config import settings
from ..services.loader import PackageError
from ..services.coverage import CoverageError, build_coverage
from ..services.release import ExceptionValidationError, decide, \
    parse_expires_at, report_version_of
from ..services.replay import replay
from ..store import store

router = APIRouter(prefix="/api")

SEVERITY_VALUES = {"breaking", "undetermined", "compatible"}
COVERAGE_SIDES = ("baseline", "candidate")


@router.get("/health")
def health():
    return {
        "status": "ok",
        "storage": store.status(),
        "max_upload_mb": settings.max_upload_mb,
        "time": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/analyses", status_code=201)
async def create_analysis(baseline: UploadFile, candidate: UploadFile):
    b_bytes = await baseline.read()
    c_bytes = await candidate.read()
    _check_size(baseline.filename, b_bytes)
    _check_size(candidate.filename, c_bytes)
    try:
        result = analyze(baseline.filename or "baseline.yaml", b_bytes,
                         candidate.filename or "candidate.yaml", c_bytes)
    except PackageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # defensive: surface parse bugs as 422
        raise HTTPException(status_code=422,
                            detail=f"分析失败: {exc.__class__.__name__}: {exc}")

    created_at = datetime.now(timezone.utc).isoformat()
    store.save(
        analysis_id=result["id"],
        baseline_name=baseline.filename or "baseline",
        candidate_name=candidate.filename or "candidate",
        baseline_meta=result["baseline_meta"],
        candidate_meta=result["candidate_meta"],
        report_doc=result["report_doc"],
        stats=result["stats"],
        created_at=created_at,
        packages=result["packages"])
    body = dict(result["report_doc"])
    body["stored"] = True
    body["storage"] = store.status()
    body["fingerprint"] = result["fingerprint"]
    return body


def _check_size(name, data):
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"文件 {name} 超过大小限制 "
                   f"{settings.max_upload_mb}MB")


@router.get("/analyses")
def list_analyses(limit: int = 50):
    return {"items": store.list_analyses(min(max(limit, 1), 200)),
            "storage": store.status()}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str):
    record = store.get(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="分析不存在")
    return record["report"]


@router.delete("/analyses/{analysis_id}")
def delete_analysis(analysis_id: str):
    if not store.get(analysis_id):
        raise HTTPException(status_code=404, detail="分析不存在")
    store.delete(analysis_id)
    return {"deleted": analysis_id}


def _parse_severity(severity: str | None) -> set[str]:
    if not severity:
        return set(SEVERITY_VALUES)
    values = {s.strip() for s in severity.split(",") if s.strip()}
    unknown = values - SEVERITY_VALUES
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"未知严重度筛选: {sorted(unknown)}，"
                   f"可选 breaking/undetermined/compatible")
    return values


@router.get("/analyses/{analysis_id}/export")
def export_analysis(analysis_id: str, severity: str | None = None):
    record = store.get(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="分析不存在")
    doc = record["report"]
    sev = _parse_severity(severity)
    if sev != SEVERITY_VALUES:
        doc = filter_report(doc, sev)
    coverage = store.get_coverage(analysis_id) or {}
    if coverage.get("baseline") is not None or \
            coverage.get("candidate") is not None:
        doc = dict(doc)
        doc["call_coverage"] = {
            side: coverage[side] for side in COVERAGE_SIDES
            if coverage.get(side) is not None}
    payload = _dumps_deterministic(doc)
    suffix = "all" if sev == SEVERITY_VALUES else "-".join(sorted(sev))
    filename = f"contract-report-{analysis_id}-{suffix}.json"
    return Response(
        content=payload, media_type="application/json",
        headers={"Content-Disposition":
                 f'attachment; filename="{filename}"',
                 "X-Report-Fingerprint": _fingerprint(payload)})


@router.post("/analyses/{analysis_id}/findings/{finding_id}/replay")
async def replay_finding(request: Request, analysis_id: str,
                         finding_id: str):
    record = store.get(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="分析不存在")
    packages = store.get_packages(analysis_id)
    if not packages:
        raise HTTPException(status_code=409,
                            detail="原始文档包不可用，无法重放")
    finding = None
    for f in record["report"]["findings"]:
        if f["id"] == finding_id:
            finding = f
            break
    if not finding:
        raise HTTPException(status_code=404, detail="结果不存在")

    override = None
    try:
        body = await request.json()
    except Exception:
        body = None
    if isinstance(body, dict) and "instance" in body:
        override = body["instance"]

    witness = finding.get("witness") or {}
    # replay module expects side descriptors
    witness = dict(witness)
    witness.setdefault("direction",
                       "response" if finding.get("location") == "response"
                       else "request")
    # structural replay dispatches on witness.kind but needs the rule to pick
    # the right semantic checks; backfill context for older stored reports
    witness.setdefault("rule", finding.get("rule"))
    for key in ("location", "media_type", "status_code"):
        witness.setdefault(key, finding.get(key))
    pkg_b = from_envelope(packages["baseline"])
    pkg_c = from_envelope(packages["candidate"])
    result = replay(pkg_b, pkg_c, witness, instance_override=override,
                    rule=finding.get("rule"))
    result["finding_id"] = finding_id
    result["rule"] = finding["rule"]
    result["message"] = finding["message"]
    return result


def _dumps_deterministic(doc) -> str:
    import json
    return json.dumps(doc, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def _fingerprint(payload: str) -> str:
    import hashlib
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------- 发布放行裁决
def _load_analysis_or_404(analysis_id: str) -> dict:
    record = store.get(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="分析不存在")
    return record


@router.put("/analyses/{analysis_id}/findings/{finding_id}/exception")
async def register_exception(request: Request, analysis_id: str,
                             finding_id: str):
    """为指定 finding 登记一条发布例外（理由 + UTC 到期时间）。

    例外绑定**当前完整报告的版本指纹**与 finding ID：同分析 ID 重算导致
    报告变化后，旧许可因版本不匹配而不生效；finding 消失或到期同样失效。
    未知 finding ID 一律拒绝（404）。同一 finding 重复登记为更新。
    """
    record = _load_analysis_or_404(analysis_id)
    # 必须基于完整 findings 校验，不接受任何筛选后的子集
    full_findings = record["report"]["findings"]
    finding = next((f for f in full_findings
                    if f["id"] == finding_id), None)
    if not finding:
        raise HTTPException(
            status_code=404,
            detail=f"finding {finding_id} 不存在于该分析的完整报告中，"
                   "不能为未知结果登记例外")
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400,
                            detail="请求体必须是 JSON 对象")
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise HTTPException(status_code=400,
                            detail="reason 必填：登记例外的放行理由")
    try:
        expires_dt = parse_expires_at(body.get("expires_at"))
    except ExceptionValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    created_by_raw = body.get("created_by")
    created_by = (created_by_raw.strip()
                  if isinstance(created_by_raw, str)
                  and created_by_raw.strip() else None)

    report_version = report_version_of(record["report"])
    now = datetime.now(timezone.utc)
    store.upsert_exception(
        analysis_id=analysis_id, report_version=report_version,
        finding_id=finding_id, reason=reason.strip(), expires_at=expires_dt,
        created_by=created_by, now_ts=now)
    decision = decide(record["report"],
                      store.list_exceptions(analysis_id), now=now)
    item = next(i for i in decision["items"]
                if i["finding_id"] == finding_id)
    return {
        "registered": True,
        "analysis_id": analysis_id,
        "finding_id": finding_id,
        "report_version": report_version,
        "exception": item["exception"],
        "exception_state": item["exception_state"],
        "basis": item["basis"],
        "verdict": decision["verdict"],
        "verdict_label": decision["verdict_label"],
        "summary": decision["summary"],
        "stored": True,
        "storage": store.status(),
    }


@router.get("/analyses/{analysis_id}/release-decision")
def get_release_decision(analysis_id: str):
    """查询逐项依据与「阻断 / 待核 / 可放行」总体裁决。

    始终读取存储中的**完整报告 findings** 与全部历史例外（含已失效者，
    随每项给出生效/失效原因）；页面严重度筛选与端点汇总不影响本结果。
    """
    record = _load_analysis_or_404(analysis_id)
    exceptions = store.list_exceptions(analysis_id)
    return decide(record["report"], exceptions)


@router.get("/analyses/{analysis_id}/exceptions")
def list_exceptions(analysis_id: str):
    _load_analysis_or_404(analysis_id)
    return {"analysis_id": analysis_id,
            "exceptions": store.list_exceptions(analysis_id),
            "storage": store.status()}


@router.delete(
    "/analyses/{analysis_id}/findings/{finding_id}/exception")
def revoke_exception(analysis_id: str, finding_id: str):
    """撤销当前报告版本上某个 finding 的例外。"""
    record = _load_analysis_or_404(analysis_id)
    report_version = report_version_of(record["report"])
    ok = store.delete_exception(analysis_id, report_version, finding_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail="当前报告版本上该 finding 没有已登记的例外")
    return {"revoked": True, "analysis_id": analysis_id,
            "finding_id": finding_id, "report_version": report_version}


# --------------------------------------------------------------- 调用覆盖
@router.post("/analyses/{analysis_id}/coverage/{side}", status_code=201)
async def upload_coverage(analysis_id: str, side: str, file: UploadFile):
    if side not in COVERAGE_SIDES:
        raise HTTPException(
            status_code=400,
            detail=f"未知文档侧 {side!r}，可选 baseline/candidate")
    record = store.get(analysis_id)
    if not record:
        raise HTTPException(status_code=404, detail="分析不存在")
    packages = store.get_packages(analysis_id)
    if not packages:
        raise HTTPException(status_code=409,
                            detail="原始文档包不可用，无法计算调用覆盖")
    raw = await file.read()
    _check_size(file.filename, raw)
    pkg = from_envelope(packages[side])
    try:
        doc = build_coverage(pkg, side, raw,
                             source_file=file.filename or "calls.ndjson")
    except CoverageError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # defensive: surface engine bugs as 422
        raise HTTPException(status_code=422,
                            detail=f"调用覆盖计算失败: "
                                   f"{exc.__class__.__name__}: {exc}")
    store.save_coverage(analysis_id, side, doc)
    body = dict(doc)
    body["stored"] = True
    body["storage"] = store.status()
    return body


@router.get("/analyses/{analysis_id}/coverage")
def list_coverage(analysis_id: str):
    if not store.get(analysis_id):
        raise HTTPException(status_code=404, detail="分析不存在")
    coverage = store.get_coverage(analysis_id) or {}
    out = []
    for side in COVERAGE_SIDES:
        doc = coverage.get(side)
        out.append({
            "side": side,
            "available": doc is not None,
            "source_file": doc.get("source_file") if doc else None,
            "summary": doc.get("summary") if doc else None,
        })
    return {"analysis_id": analysis_id, "sides": out,
            "storage": store.status()}


@router.get("/analyses/{analysis_id}/coverage/{side}")
def get_coverage(analysis_id: str, side: str):
    if side not in COVERAGE_SIDES:
        raise HTTPException(
            status_code=400,
            detail=f"未知文档侧 {side!r}，可选 baseline/candidate")
    if not store.get(analysis_id):
        raise HTTPException(status_code=404, detail="分析不存在")
    coverage = store.get_coverage(analysis_id) or {}
    doc = coverage.get(side)
    if doc is None:
        raise HTTPException(status_code=404,
                            detail=f"该分析尚未上传{side}侧调用覆盖")
    return doc


@router.delete("/analyses/{analysis_id}/coverage/{side}", status_code=200)
def delete_coverage(analysis_id: str, side: str):
    if side not in COVERAGE_SIDES:
        raise HTTPException(
            status_code=400,
            detail=f"未知文档侧 {side!r}，可选 baseline/candidate")
    if not store.get(analysis_id):
        raise HTTPException(status_code=404, detail="分析不存在")
    coverage = store.get_coverage(analysis_id) or {}
    if coverage.get(side) is None:
        raise HTTPException(status_code=404,
                            detail=f"该分析尚未上传{side}侧调用覆盖")
    store.delete_coverage(analysis_id, side)
    return {"deleted": analysis_id, "side": side}


@router.get("/analyses/{analysis_id}/coverage/{side}/export")
def export_coverage(analysis_id: str, side: str):
    if side not in COVERAGE_SIDES:
        raise HTTPException(
            status_code=400,
            detail=f"未知文档侧 {side!r}，可选 baseline/candidate")
    if not store.get(analysis_id):
        raise HTTPException(status_code=404, detail="分析不存在")
    coverage = store.get_coverage(analysis_id) or {}
    doc = coverage.get(side)
    if doc is None:
        raise HTTPException(status_code=404,
                            detail=f"该分析尚未上传{side}侧调用覆盖")
    payload = _dumps_deterministic(doc)
    filename = f"call-coverage-{analysis_id}-{side}.json"
    return Response(
        content=payload, media_type="application/json",
        headers={"Content-Disposition":
                 f'attachment; filename="{filename}"',
                 "X-Coverage-Fingerprint": _fingerprint(payload)})
