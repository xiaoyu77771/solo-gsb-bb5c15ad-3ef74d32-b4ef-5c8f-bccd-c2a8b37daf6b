"""FastAPI 入口：全部数据随请求在本地内存中处理。

* POST /resolve     提交仓库快照 + 根包 + 版本约束 + 目标环境（PEP 508 marker
  在请求环境下求值），返回锁定清单或冲突来源链
* POST /resolve-matrix
  同一份快照 + 根约束 + 2～8 个带唯一 id 的目标环境：逐环境复用 /resolve
  规则求解，全部成功时返回按 id 排序的各环境 locked 与按包名排序的跨环境
  版本矩阵（shared/divergent）；任一环境无解则整体 409，列出各失败环境的
  原冲突结果
* POST /upgrade     在 /resolve 语义基础上附加 current_lock 与单个升级目标：
  仅考虑严格高于当前版本的候选，取能完成整体解析的最高版本，并在该版本
  的所有有效解中最小化非目标包相对 current_lock 的变化数量
* POST /audit-lock  只审计不求解：按 current_lock 的锁定版本从根包遍历
  已激活依赖，报告 missing/unavailable/constraint_mismatch/extraneous
* POST /dependency-paths
  先按 /audit-lock 规则校验 current_lock；无效返回 409 审计问题，
  有效则按锁定版本与目标环境已激活依赖建图，返回根包到目标包的
  全部最短包路径（菱形保留等长路径，环安全、确定性排序）
* POST /sbom
  先按 /audit-lock 规则校验 current_lock；无效返回 409 审计问题，
  有效则沿已激活依赖图生成确定性 JSON 清单：每包含规范化名称、版本、
  PURL、依赖名称与候选版本携带的 source_url/sha256/license 元数据；
  缺失元数据只形成 warnings，不阻断导出；结果按包名排序
* GET  /healthz     健康检查
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from packaging.version import Version

from .audit import audit_lock
from .paths import build_locked_graph, shortest_paths
from .repository import (
    SnapshotError,
    build_repository,
    canonical,
    parse_current_lock,
    parse_root_specifier,
)
from .resolver import ResolutionLimit, Resolver
from .sbom import build_sbom
from .schemas import (
    AuditLockRequest,
    AuditLockResponse,
    DependencyPathsRequest,
    DependencyPathsResponse,
    InvalidLockResponse,
    InvalidSnapshotResponse,
    ResolveMatrixRequest,
    ResolveMatrixResponse,
    MatrixUnresolvedResponse,
    ResolveRequest,
    ResolveResponse,
    SbomRequest,
    SbomResponse,
    UnresolvedResponse,
    UpgradeRequest,
    UpgradeResponse,
)

app = FastAPI(
    title="本地依赖解析 API",
    description=(
        "基于 Python packaging（PEP 440/503/508）与回溯搜索的依赖求解器。"
        "所有仓库数据与目标环境随请求提交，本地解析，不访问任何远程索引、"
        "不读取宿主机平台信息。"
    ),
    version="1.5.0",
)


def _conflict_payload(raw: dict) -> dict:
    """把 Resolver.build_conflicts() 的内部结构转为对外 JSON。"""
    return {
        "status": raw["status"],
        "message": raw["message"],
        "conflicts": [
            {
                "subject": c.subject,
                "kind": c.kind,
                "message": c.message,
                "constraints": [
                    {
                        "chain": [
                            {
                                "package": link.package,
                                "version": link.version,
                                "requires": link.requires,
                            }
                            for link in chain
                        ]
                    }
                    for chain in c.chains
                ],
                "partial_selection": c.partial_selection,
            }
            for c in raw["_conflicts"]
        ],
    }


@app.get("/healthz", summary="健康检查")
def healthz() -> dict:
    return {"status": "ok"}


def _resolve_once(
    *,
    repository_payload: dict,
    target_environment: dict,
    root_canonical: str,
    specifier: str,
    allow_prereleases: bool,
) -> tuple[dict | None, dict | None]:
    """按 /resolve 的既有规则对单个目标环境求解一次。

    返回 ``(ok_payload, conflict_payload)``，二者恰有一个非 None：

    * 成功：``ok_payload`` 为 build_output 的 200 响应体；
    * 无解或超上限：``conflict_payload`` 为 _conflict_payload 的 409 响应体。

    快照/约束构造期的 SnapshotError 不在此捕获，由调用方映射为 422。
    """
    repo = build_repository(repository_payload, target_environment)
    root_spec = parse_root_specifier(specifier)

    resolver = Resolver(repo, allow_prereleases=allow_prereleases)
    try:
        state = resolver.resolve(root_canonical, root_spec, specifier)
    except ResolutionLimit:
        return None, _conflict_payload(resolver.build_conflicts(limit=True))

    if state is not None:
        return resolver.build_output(state, root_canonical), None
    return None, _conflict_payload(resolver.build_conflicts())


@app.post(
    "/resolve",
    summary="解析依赖并生成确定性锁定清单",
    response_model=ResolveResponse,
    responses={
        409: {"model": UnresolvedResponse, "description": "约束无解或超过搜索上限"},
        422: {"model": InvalidSnapshotResponse, "description": "快照或请求非法"},
    },
)
def resolve(request: ResolveRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    resolver = Resolver(repo, allow_prereleases=request.allow_prereleases)
    try:
        state = resolver.resolve(root_canonical, root_spec, request.specifier)
    except ResolutionLimit:
        return JSONResponse(
            status_code=409,
            content=_conflict_payload(resolver.build_conflicts(limit=True)),
        )

    if state is not None:
        return resolver.build_output(state, root_canonical)

    return JSONResponse(
        status_code=409,
        content=_conflict_payload(resolver.build_conflicts()),
    )


@app.post(
    "/resolve-matrix",
    summary="同一份快照在 2～8 个目标环境下分别求解并给出跨环境版本矩阵",
    response_model=ResolveMatrixResponse,
    responses={
        409: {
            "model": MatrixUnresolvedResponse,
            "description": "任一目标环境无解：列出各失败环境的原冲突结果",
        },
        422: {"model": InvalidSnapshotResponse, "description": "快照或请求非法（含重复 id）"},
    },
)
def resolve_matrix(request: ResolveMatrixRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    # id 唯一性在路由层校验：Pydantic 的 pattern/min_length 负责格式，
    # 重复值在此返回 422，不进入任何求解。
    seen: set[str] = set()
    for env in request.target_environments:
        if env.id in seen:
            return JSONResponse(
                status_code=422,
                content={
                    "status": "invalid_snapshot",
                    "message": f"target_environments 的 id {env.id!r} 重复，必须唯一",
                },
            )
        seen.add(env.id)

    # marker 解析/求值与根约束非法属于 422；根包只查一次（与环境无关）。
    try:
        repo_known = build_repository(
            payload["repository"], payload["target_environments"][0]
        )
        parse_root_specifier(request.specifier)
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo_known.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 逐环境独立求解：每个环境一个全新 Resolver，冲突收集互不干扰；
    # 即使某环境已无解也继续跑完全部环境，以便 409 列出所有失败环境。
    successes: dict[str, dict] = {}
    failures: list[dict] = []
    for env in payload["target_environments"]:
        env_id = env["id"]
        try:
            ok, conflict = _resolve_once(
                repository_payload=payload["repository"],
                target_environment=env,
                root_canonical=root_canonical,
                specifier=request.specifier,
                allow_prereleases=request.allow_prereleases,
            )
        except SnapshotError as exc:
            return JSONResponse(
                status_code=422,
                content={"status": "invalid_snapshot", "message": str(exc)},
            )
        if ok is not None:
            successes[env_id] = ok
        else:
            assert conflict is not None
            failures.append({"id": env_id, **conflict})

    if failures:
        failures.sort(key=lambda f: f["id"])
        ids = "、".join(f["id"] for f in failures)
        return JSONResponse(
            status_code=409,
            content={
                "status": "conflict",
                "message": (
                    f"{len(failures)} 个目标环境无解（共 "
                    f"{len(request.target_environments)} 个）：{ids}"
                ),
                "failures": failures,
            },
        )

    # 全部成功：results 按 id 排序；matrix 按包名排序，逐包收集各环境版本。
    ordered_ids = sorted(successes)
    results = [
        {
            "id": env_id,
            "root_version": successes[env_id]["root_version"],
            "locked": successes[env_id]["locked"],
        }
        for env_id in ordered_ids
    ]
    all_packages = sorted(
        {pkg for ok in successes.values() for pkg in ok["locked"]}
    )
    matrix = []
    for pkg in all_packages:
        versions = {
            env_id: successes[env_id]["locked"].get(pkg) for env_id in ordered_ids
        }
        resolved = [v for v in versions.values() if v is not None]
        state = (
            "shared"
            if len(resolved) == len(ordered_ids)
            and len(set(resolved)) == 1
            else "divergent"
        )
        matrix.append({"name": pkg, "versions": versions, "state": state})

    return {
        "status": "ok",
        "root": root_canonical,
        "results": results,
        "matrix": matrix,
    }


def _lock_changes(
    current: dict[str, Version], locked: dict[str, str]
) -> list[dict]:
    """current_lock 与新锁定清单的逐项差异，按包名排序。

    版本按 PEP 440 比较（如 1.0 与 1.0.0 视为相同，不产生变化项）；
    新增包 from 为 None，被删除的包 to 为 None。
    """
    changes = []
    for name in sorted(set(current) | set(locked)):
        old = current.get(name)
        new = locked.get(name)
        if old is not None and new is not None and old == Version(new):
            continue
        changes.append(
            {
                "name": name,
                "from": str(old) if old is not None else None,
                "to": new,
            }
        )
    return changes


@app.post(
    "/upgrade",
    summary="在现有锁定清单上升级单个目标包",
    response_model=UpgradeResponse,
    responses={
        409: {"model": UnresolvedResponse, "description": "无可行升级或超过搜索上限"},
        422: {"model": InvalidSnapshotResponse, "description": "快照、current_lock 或请求非法"},
    },
)
def upgrade(request: UpgradeRequest):
    root_canonical = canonical(request.root)
    target_canonical = canonical(request.target)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    if target_canonical not in current_lock:
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"目标包 {target_canonical!r} 不存在于 current_lock 中",
            },
        )

    resolver = Resolver(repo, allow_prereleases=request.allow_prereleases)
    try:
        state = resolver.upgrade(
            root_canonical,
            root_spec,
            request.specifier,
            target=target_canonical,
            current_version=current_lock[target_canonical],
            reference=current_lock,
        )
    except ResolutionLimit:
        return JSONResponse(
            status_code=409,
            content=_conflict_payload(resolver.build_conflicts(limit=True)),
        )

    if state is None:
        content = _conflict_payload(resolver.build_conflicts())
        content["message"] = (
            f"目标包 {target_canonical!r} 没有可行的升级："
            "不存在严格高于当前版本且能完成整体解析的候选版本"
        )
        return JSONResponse(status_code=409, content=content)

    locked = {pkg: str(ver) for pkg, ver in sorted(state.selection.items())}
    return {
        "status": "ok",
        "root": root_canonical,
        "root_version": str(state.selection[root_canonical]),
        "locked": locked,
        "changes": _lock_changes(current_lock, locked),
    }


@app.post(
    "/audit-lock",
    summary="审计现有锁定清单而不重新求解",
    response_model=AuditLockResponse,
    responses={
        422: {"model": InvalidSnapshotResponse, "description": "快照或 current_lock 非法"},
    },
)
def audit_lock_endpoint(request: AuditLockRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    return {"status": "ok", **result}


@app.post(
    "/dependency-paths",
    summary="解释目标包为何出现在锁定清单中：根包到目标包的全部最短路径",
    response_model=DependencyPathsResponse,
    responses={
        409: {"model": InvalidLockResponse, "description": "锁定清单未通过审计"},
        422: {"model": InvalidSnapshotResponse, "description": "快照或 current_lock 非法"},
    },
)
def dependency_paths_endpoint(request: DependencyPathsRequest):
    root_canonical = canonical(request.root)
    target_canonical = canonical(request.target)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 先按现有审计规则校验锁定清单；无效则带确定性排序的问题返回 409，
    # 不执行任何路径查询。
    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    if not result["valid"]:
        return JSONResponse(
            status_code=409,
            content={
                "status": "invalid_lock",
                "message": "锁定清单未通过审计，未执行路径查询",
                "issues": result["issues"],
            },
        )

    # 有效锁：按锁定版本与目标环境激活的依赖建图（无版本选择）。
    graph = build_locked_graph(
        repo, root_name=root_canonical, current_lock=current_lock
    )
    paths = shortest_paths(graph, root_canonical, target_canonical)
    return {
        "status": "ok",
        "root": root_canonical,
        "target": target_canonical,
        "reachable": bool(paths),
        "paths": paths,
    }


@app.post(
    "/sbom",
    summary="沿有效锁定清单的已激活依赖图导出确定性 JSON SBOM",
    response_model=SbomResponse,
    responses={
        409: {"model": InvalidLockResponse, "description": "锁定清单未通过审计"},
        422: {"model": InvalidSnapshotResponse, "description": "快照或 current_lock 非法"},
    },
)
def sbom_endpoint(request: SbomRequest):
    root_canonical = canonical(request.root)
    payload = request.model_dump()

    try:
        repo = build_repository(payload["repository"], payload["target_environment"])
        root_spec = parse_root_specifier(request.specifier)
        current_lock = parse_current_lock(payload["current_lock"])
    except SnapshotError as exc:
        return JSONResponse(
            status_code=422,
            content={"status": "invalid_snapshot", "message": str(exc)},
        )

    if not repo.known(root_canonical):
        return JSONResponse(
            status_code=422,
            content={
                "status": "invalid_snapshot",
                "message": f"根包 {root_canonical!r} 不存在于仓库快照中",
            },
        )

    # 先按现有审计规则校验锁定清单；无效则带确定性排序的问题返回 409，
    # 不导出任何清单。
    result = audit_lock(
        repo,
        root_name=root_canonical,
        root_spec=root_spec,
        root_raw=request.specifier,
        current_lock=current_lock,
        allow_prereleases=request.allow_prereleases,
    )
    if not result["valid"]:
        return JSONResponse(
            status_code=409,
            content={
                "status": "invalid_lock",
                "message": "锁定清单未通过审计，未导出 SBOM",
                "issues": result["issues"],
            },
        )

    # 有效锁：按锁定版本与目标环境激活的依赖建图（无版本选择），再导出。
    graph = build_locked_graph(
        repo, root_name=root_canonical, current_lock=current_lock
    )
    document = build_sbom(
        repo,
        root_name=root_canonical,
        current_lock=current_lock,
        graph=graph,
    )
    return {"status": "ok", "root": root_canonical, **document}
