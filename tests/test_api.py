"""FastAPI 路由层测试。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def payload(**overrides):
    base = {
        "repository": {
            "app": [
                {"version": "1.0.0",
                 "dependencies": [{"name": "libx", "specifier": ">=1.0"}]},
            ],
            "libx": [
                {"version": "1.0", "dependencies": []},
                {"version": "2.0",
                 "dependencies": [{"name": "liby", "specifier": ""}]},
            ],
            "liby": [{"version": "1.1"}, {"version": "0.9"}],
        },
        "root": "app",
        "specifier": "",
        "allow_prereleases": False,
        "target_environment": {
            "python_version": "3.11",
            "sys_platform": "linux",
            "platform_machine": "x86_64",
        },
    }
    base.update(overrides)
    return base


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_resolve_ok():
    r = client.post("/resolve", json=payload())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["root_version"] == "1.0.0"
    assert body["locked"] == {"app": "1.0.0", "libx": "2.0", "liby": "1.1"}
    assert body["edges"][0] == {"from": "root", "to": "app", "specifier": "*"}
    assert {"from": "libx==2.0", "to": "liby", "specifier": "*"} in body["edges"]


def test_resolve_conflict_409():
    repo = {
        "app": [{"version": "1.0",
                 "dependencies": [
                     {"name": "left", "specifier": ""},
                     {"name": "right", "specifier": ""},
                 ]}],
        "left": [{"version": "1.0",
                  "dependencies": [{"name": "core", "specifier": "==1.0"}]}],
        "right": [{"version": "1.0",
                   "dependencies": [{"name": "core", "specifier": "==2.0"}]}],
        "core": [{"version": "1.0"}, {"version": "2.0"}],
    }
    r = client.post("/resolve", json=payload(repository=repo))
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    conflict = body["conflicts"][0]
    assert conflict["subject"] == "core"
    # 每条约束都带来源链，且链从根需求开始
    for entry in conflict["constraints"]:
        chain = entry["chain"]
        assert chain[0]["package"] is None
        assert chain[-1]["requires"] in {"==1.0", "==2.0"}
    assert conflict["partial_selection"]["app"] == "1.0"


def test_resolve_unknown_root_422():
    r = client.post("/resolve", json=payload(root="missing"))
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_resolve_bad_version_422():
    repo = {"app": [{"version": "oops", "dependencies": []}]}
    r = client.post("/resolve", json=payload(repository=repo))
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_resolve_bad_specifier_422():
    repo = {"app": [{"version": "1.0",
                     "dependencies": [{"name": "x", "specifier": ">>>1"}]}]}
    r = client.post("/resolve", json=payload(repository=repo))
    assert r.status_code == 422


def test_pydantic_validation_error_on_extra_field():
    r = client.post("/resolve", json=payload(unknown_field=1))
    assert r.status_code == 422


def test_prerelease_toggle():
    repo = {
        "app": [{"version": "1.0",
                 "dependencies": [{"name": "lib", "specifier": ""}]}],
        "lib": [{"version": "2.0rc1"}, {"version": "1.9"}],
    }
    r1 = client.post("/resolve", json=payload(repository=repo))
    assert r1.json()["locked"]["lib"] == "1.9"
    r2 = client.post(
        "/resolve", json=payload(repository=repo, allow_prereleases=True)
    )
    assert r2.json()["locked"]["lib"] == "2.0rc1"


# --------------------------------------------------------------------- #
# PEP 508 marker / target_environment
# --------------------------------------------------------------------- #
LINUX_X64_PY311 = {
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}


def _marker_repo():
    return {
        "app": [
            {"version": "2.0",
             "dependencies": [
                 {"name": "linux-only", "specifier": "",
                  "marker": "sys_platform == 'linux'"},
                 {"name": "win-only", "specifier": "",
                  "marker": "sys_platform == 'win32'"},
                 {"name": "arm-accel", "specifier": "",
                  "marker": "platform_machine == 'aarch64'"},
                 {"name": "modern-core", "specifier": ">=2",
                  "marker": "python_version >= '3.10'"},
                 {"name": "legacy-core", "specifier": "",
                  "marker": "python_version < '3.10'"},
             ]}
        ],
        "linux-only": [{"version": "1.0"}],
        "win-only": [{"version": "1.0"}],
        "arm-accel": [{"version": "1.0"}],
        "modern-core": [{"version": "2.0"}, {"version": "3.0"}],
        "legacy-core": [{"version": "0.9"}],
    }


def test_markers_linux_environment():
    r = client.post("/resolve", json=payload(
        repository=_marker_repo(), target_environment=LINUX_X64_PY311))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"] == {
        "app": "2.0", "linux-only": "1.0", "modern-core": "3.0"
    }
    tos = {e["to"] for e in body["edges"]}
    assert tos == {"app", "linux-only", "modern-core"}


def test_markers_same_snapshot_windows_environment():
    """跨环境：同一仓库快照仅改 target_environment，锁定结果随之变化。"""
    env = {"python_version": "3.9", "sys_platform": "win32",
           "platform_machine": "AMD64"}
    r = client.post("/resolve", json=payload(
        repository=_marker_repo(), target_environment=env))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"] == {
        "app": "2.0", "legacy-core": "0.9", "win-only": "1.0"
    }
    tos = {e["to"] for e in body["edges"]}
    assert not (tos & {"linux-only", "arm-accel", "modern-core"})


def test_markers_cross_environment_deterministic():
    body1 = client.post("/resolve", json=payload(
        repository=_marker_repo(), target_environment=LINUX_X64_PY311)).json()
    body2 = client.post("/resolve", json=payload(
        repository=_marker_repo(),
        target_environment=dict(reversed(list(LINUX_X64_PY311.items()))))).json()
    assert body1 == body2


def test_marker_inactive_unsatisfiable_dependency_ignored():
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "win-thing", "specifier": ">=42",
             "marker": "sys_platform == 'win32'"},
            {"name": "real", "specifier": "==1.0"},
        ]}],
        "real": [{"version": "1.0"}],
    }
    r = client.post("/resolve", json=payload(
        repository=repo, target_environment=LINUX_X64_PY311))
    assert r.status_code == 200, r.text
    assert r.json()["locked"] == {"app": "1.0", "real": "1.0"}


def test_marker_active_conflict_reports_chain_409():
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "left", "specifier": "",
             "marker": "sys_platform == 'linux'"},
            {"name": "right", "specifier": "",
             "marker": "sys_platform == 'linux'"},
        ]}],
        "left": [{"version": "1.0", "dependencies": [
            {"name": "core", "specifier": "==1.0"}]}],
        "right": [{"version": "1.0", "dependencies": [
            {"name": "core", "specifier": "==2.0"}]}],
        "core": [{"version": "1.0"}, {"version": "2.0"}],
    }
    r = client.post("/resolve", json=payload(
        repository=repo, target_environment=LINUX_X64_PY311))
    assert r.status_code == 409
    assert r.json()["conflicts"][0]["subject"] == "core"

    # 切到 win32：两条约束来源均未激活，冲突消失。
    r2 = client.post("/resolve", json=payload(
        repository=repo,
        target_environment={"python_version": "3.11",
                            "sys_platform": "win32",
                            "platform_machine": "AMD64"}))
    assert r2.status_code == 200
    assert r2.json()["locked"] == {"app": "1.0"}


def test_invalid_marker_syntax_422_locates_package_version_dependency():
    repo = {
        "app": [{"version": "1.2.3", "dependencies": [
            {"name": "some-dep", "specifier": ">=1",
             "marker": "python_version >>> '3.9'"}]}]
    }
    r = client.post("/resolve", json=payload(
        repository=repo, target_environment=LINUX_X64_PY311))
    assert r.status_code == 422, r.text
    message = r.json()["message"]
    assert r.json()["status"] == "invalid_snapshot"
    assert "app==1.2.3" in message
    assert "some-dep" in message
    assert "PEP 508" in message


def test_marker_out_of_scope_variable_422():
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "x", "specifier": "",
             "marker": "implementation_name == 'cpython'"}]}]
    }
    r = client.post("/resolve", json=payload(
        repository=repo, target_environment=LINUX_X64_PY311))
    assert r.status_code == 422
    message = r.json()["message"]
    assert "implementation_name" in message
    assert "app==1.0" in message and "'x'" in message


def test_marker_extra_variable_422():
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "x", "specifier": "", "marker": "extra == 'speedups'"}]}]
    }
    r = client.post("/resolve", json=payload(
        repository=repo, target_environment=LINUX_X64_PY311))
    assert r.status_code == 422
    assert "extra" in r.json()["message"]


def test_target_environment_required_422():
    body = payload()
    del body["target_environment"]
    r = client.post("/resolve", json=body)
    assert r.status_code == 422


def test_target_environment_fields_required_422():
    body = payload()
    body["target_environment"] = {"python_version": "3.11",
                                  "sys_platform": "linux"}
    r = client.post("/resolve", json=body)
    assert r.status_code == 422


def test_target_environment_no_extra_fields_422():
    body = payload()
    body["target_environment"]["os_name"] = "posix"
    r = client.post("/resolve", json=body)
    assert r.status_code == 422


def test_target_environment_bad_python_version_422():
    env = dict(LINUX_X64_PY311, python_version="not-a-version")
    r = client.post("/resolve", json=payload(target_environment=env))
    assert r.status_code == 422
    assert "python_version" in r.json()["message"]


def test_target_environment_blank_value_422():
    env = dict(LINUX_X64_PY311, sys_platform="   ")
    r = client.post("/resolve", json=payload(target_environment=env))
    assert r.status_code == 422
    assert "target_environment" in r.json()["message"]


def test_dependency_marker_extra_field_forbidden_422():
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "x", "specifier": "", "markers": "sys_platform=='linux'"}]}]
    }
    r = client.post("/resolve", json=payload(repository=repo))
    assert r.status_code == 422


def test_environment_values_taken_from_request_not_host():
    """宿主为 linux 也必须按请求的 win32 环境求值（不读取真实平台）。"""
    repo = {
        "app": [{"version": "1.0", "dependencies": [
            {"name": "win-only", "specifier": "",
             "marker": "sys_platform == 'win32'"},
        ]}],
        "win-only": [{"version": "1.0"}],
    }
    env = {"python_version": "3.11", "sys_platform": "win32",
           "platform_machine": "AMD64"}
    r = client.post("/resolve", json=payload(
        repository=repo, target_environment=env))
    assert r.status_code == 200, r.text
    assert "win-only" in r.json()["locked"]
