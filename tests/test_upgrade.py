"""POST /upgrade 的端到端测试。

覆盖：最高可行版本选择、非目标包变更最小化、确定性平局、新增/删除/变更
的 changes 报告、422/409 映射、marker 语义复用，以及 /resolve 行为不变。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ENV = {
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}


def c(version, deps=None):
    return {"version": version, "dependencies": deps or []}


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def upgrade(repo, lock, target, *, env=None, **overrides):
    body = {
        "repository": repo,
        "root": "app",
        "target_environment": env or ENV,
        "current_lock": lock,
        "target": target,
    }
    body.update(overrides)
    return client.post("/upgrade", json=body)


# --------------------------------------------------------------------- #
# 1. 基本升级：仅严格更高版本；非目标包变更最小化
# --------------------------------------------------------------------- #
def test_upgrade_basic_and_minimizes_non_target_changes():
    """liby 有 2.0 可用，但保持 current_lock 的 1.0 变更数更少（0 vs 1）。"""
    repo = {
        "app": [c("1.0", [d("libx"), d("liby")])],
        "libx": [c("1.0"), c("2.0")],
        "liby": [c("1.0"), c("2.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "liby": "1.0"}
    r = upgrade(repo, lock, "libx")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["locked"] == {"app": "1.0", "libx": "2.0", "liby": "1.0"}
    assert body["changes"] == [{"name": "libx", "from": "1.0", "to": "2.0"}]
    # 对照：普通 /resolve 在同一快照下会取 liby 的最高版本
    r2 = client.post("/resolve", json={
        "repository": repo, "root": "app", "target_environment": ENV,
    })
    assert r2.json()["locked"]["liby"] == "2.0"


def test_upgrade_minimization_requires_backtracking():
    """首个找到的解（libb 2.0 + libc 2.0，2 处变更）应被更优解
    （libb 1.0 + libc 1.0，0 处非目标变更）取代。"""
    repo = {
        "app": [c("1.0", [d("libx"), d("libb")])],
        "libx": [c("1.0"), c("2.0", [d("libc", ">=1.0")])],
        "libb": [c("1.0", [d("libc", "<2.0")]), c("2.0", [d("libc", ">=2.0")])],
        "libc": [c("1.0"), c("2.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "libb": "1.0", "libc": "1.0"}
    r = upgrade(repo, lock, "libx")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"] == {
        "app": "1.0", "libx": "2.0", "libb": "1.0", "libc": "1.0",
    }
    assert body["changes"] == [{"name": "libx", "from": "1.0", "to": "2.0"}]


def test_upgrade_tie_breaks_by_deterministic_version_order():
    """liby 被迫变更（>=2.0）：2.0 与 3.0 变更数相同，取确定性顺序的最高者。"""
    repo = {
        "app": [c("1.0", [d("libx"), d("liby")])],
        "libx": [c("1.0"), c("2.0", [d("liby", ">=2.0")])],
        "liby": [c("1.0"), c("2.0"), c("3.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "liby": "1.0"}
    r = upgrade(repo, lock, "libx")
    assert r.status_code == 200, r.text
    assert r.json()["locked"]["liby"] == "3.0"


# --------------------------------------------------------------------- #
# 2. 目标版本：取能完成整体解析的最高候选
# --------------------------------------------------------------------- #
def test_upgrade_picks_highest_feasible_target_version():
    """3.0 的传递依赖无解 -> 回退到可解析的 2.0。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [
            c("1.0"),
            c("2.0"),
            c("3.0", [d("ghost", ">=9")]),
        ],
    }
    r = upgrade(repo, {"app": "1.0", "libx": "1.0"}, "libx")
    assert r.status_code == 200, r.text
    assert r.json()["locked"]["libx"] == "2.0"


def test_upgrade_root_package_as_target():
    repo = {
        "app": [c("1.0"), c("2.0", [d("liba")])],
        "liba": [c("1.0")],
    }
    r = upgrade(repo, {"app": "1.0"}, "app")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["root_version"] == "2.0"
    assert body["locked"] == {"app": "2.0", "liba": "1.0"}
    assert body["changes"] == [
        {"name": "app", "from": "1.0", "to": "2.0"},
        {"name": "liba", "from": None, "to": "1.0"},
    ]


# --------------------------------------------------------------------- #
# 3. changes：新增（from=null）、删除（to=null）、按包名排序
# --------------------------------------------------------------------- #
def test_upgrade_changes_add_remove_and_sorting():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [
            c("1.0", [d("old-dep")]),
            c("2.0", [d("new-dep")]),
        ],
        "old-dep": [c("1.0")],
        "new-dep": [c("1.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "old-dep": "1.0"}
    r = upgrade(repo, lock, "libx")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"] == {"app": "1.0", "libx": "2.0", "new-dep": "1.0"}
    # 按包名排序：libx < new-dep < old-dep
    assert body["changes"] == [
        {"name": "libx", "from": "1.0", "to": "2.0"},
        {"name": "new-dep", "from": None, "to": "1.0"},
        {"name": "old-dep", "from": "1.0", "to": None},
    ]


def test_upgrade_version_equivalence_produces_no_change():
    """current_lock 的 1.0 与仓库的 1.0.0 按 PEP 440 相等，不产生变更项。"""
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0", [d("liby")])],
        "liby": [c("1.0.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "liby": "1.0"}
    r = upgrade(repo, lock, "libx")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"]["liby"] == "1.0.0"
    assert body["changes"] == [{"name": "libx", "from": "1.0", "to": "2.0"}]


def test_upgrade_lock_keys_and_target_are_canonicalized():
    """current_lock 键与 target 都按 PEP 503 规范化匹配。"""
    repo = {
        "app": [c("1.0", [d("Lib_X")])],
        "lib-x": [c("1.0"), c("2.0")],
    }
    r = upgrade(repo, {"app": "1.0", "Lib.X": "1.0"}, "LIB_X")
    assert r.status_code == 200, r.text
    assert r.json()["changes"] == [{"name": "lib-x", "from": "1.0", "to": "2.0"}]


# --------------------------------------------------------------------- #
# 4. 422：目标不在 current_lock、非法锁版本、缺字段、多余字段
# --------------------------------------------------------------------- #
def test_upgrade_target_not_in_current_lock_422():
    repo = {"app": [c("1.0")]}
    r = upgrade(repo, {"app": "1.0"}, "ghost")
    assert r.status_code == 422
    body = r.json()
    assert body["status"] == "invalid_snapshot"
    assert "ghost" in body["message"]
    assert "current_lock" in body["message"]


def test_upgrade_invalid_lock_version_422():
    repo = {"app": [c("1.0")]}
    r = upgrade(repo, {"app": "not-a-version"}, "app")
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_upgrade_conflicting_lock_versions_422():
    repo = {"app": [c("1.0")]}
    r = upgrade(repo, {"LibX": "1.0", "lib-x": "2.0"}, "app")
    assert r.status_code == 422


def test_upgrade_missing_current_lock_422():
    body = {
        "repository": {"app": [c("1.0")]},
        "root": "app",
        "target_environment": ENV,
        "target": "app",
    }
    r = client.post("/upgrade", json=body)
    assert r.status_code == 422


def test_upgrade_extra_field_forbidden_422():
    repo = {"app": [c("1.0")]}
    r = upgrade(repo, {"app": "1.0"}, "app", unknown_field=1)
    assert r.status_code == 422


def test_upgrade_unknown_root_422():
    repo = {"app": [c("1.0")]}
    r = client.post("/upgrade", json={
        "repository": repo, "root": "missing", "target_environment": ENV,
        "current_lock": {"app": "1.0"}, "target": "app",
    })
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


# --------------------------------------------------------------------- #
# 5. 409：无可行升级
# --------------------------------------------------------------------- #
def test_upgrade_no_higher_version_409():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0")],
    }
    r = upgrade(repo, {"app": "1.0", "libx": "2.0"}, "libx")
    assert r.status_code == 409
    assert r.json()["status"] == "conflict"


def test_upgrade_all_higher_versions_infeasible_409():
    repo = {
        "app": [c("1.0", [d("libx"), d("liby")])],
        "libx": [c("1.0"), c("2.0", [d("liby", ">=2.0")])],
        "liby": [c("1.0")],  # app 钉死了 liby==1.0（唯一候选），与 >=2.0 冲突
    }
    r = upgrade(repo, {"app": "1.0", "libx": "1.0", "liby": "1.0"}, "libx")
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    assert "libx" in body["message"]
    assert body["conflicts"]  # 复用 /resolve 的冲突来源链结构
    assert body["conflicts"][0]["constraints"]


def test_upgrade_target_absent_from_repository_409():
    """target 在 current_lock 中但不在快照里：没有更高候选 -> 409。"""
    repo = {"app": [c("1.0")]}
    r = upgrade(repo, {"app": "1.0", "ghost": "1.0"}, "ghost")
    assert r.status_code == 409


# --------------------------------------------------------------------- #
# 6. marker / 目标环境语义与 /resolve 一致
# --------------------------------------------------------------------- #
def test_upgrade_respects_target_environment_markers():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [
            c("1.0"),
            c("2.0", [
                d("win-lib", marker="sys_platform == 'win32'"),
                d("posix-lib", marker="sys_platform == 'linux'"),
            ]),
        ],
        "win-lib": [c("1.0")],
        "posix-lib": [c("1.0")],
    }
    lock = {"app": "1.0", "libx": "1.0"}
    r = upgrade(repo, lock, "libx")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["locked"] == {"app": "1.0", "libx": "2.0", "posix-lib": "1.0"}
    assert body["changes"] == [
        {"name": "libx", "from": "1.0", "to": "2.0"},
        {"name": "posix-lib", "from": None, "to": "1.0"},
    ]

    win_env = {"python_version": "3.11", "sys_platform": "win32",
               "platform_machine": "AMD64"}
    r2 = upgrade(repo, lock, "libx", env=win_env)
    assert r2.json()["locked"] == {"app": "1.0", "libx": "2.0", "win-lib": "1.0"}


def test_upgrade_invalid_marker_still_422():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0", [d("x", marker="os_name == 'posix'")])],
    }
    r = upgrade(repo, {"app": "1.0", "libx": "1.0"}, "libx")
    assert r.status_code == 422
    assert "os_name" in r.json()["message"]


# --------------------------------------------------------------------- #
# 7. 预发布与确定性
# --------------------------------------------------------------------- #
def test_upgrade_prerelease_candidates_follow_toggle():
    repo = {
        "app": [c("1.0", [d("libx")])],
        "libx": [c("1.0"), c("2.0rc1")],
    }
    lock = {"app": "1.0", "libx": "1.0"}
    r = upgrade(repo, lock, "libx")
    assert r.status_code == 409  # 默认不考虑预发布，无更高稳定版

    r2 = upgrade(repo, lock, "libx", allow_prereleases=True)
    assert r2.status_code == 200, r2.text
    assert r2.json()["locked"]["libx"] == "2.0rc1"


def test_upgrade_deterministic_across_repeated_calls():
    repo = {
        "app": [c("1.0", [d("libx"), d("liby")])],
        "libx": [c("1.0"), c("2.0", [d("shared", ">=1.0")])],
        "liby": [c("1.0", [d("shared", "<2.0")])],
        "shared": [c("1.0"), c("2.0")],
    }
    lock = {"app": "1.0", "libx": "1.0", "liby": "1.0", "shared": "1.0"}
    body1 = upgrade(repo, lock, "libx").json()
    body2 = upgrade(repo, lock, "libx").json()
    assert body1 == body2
    assert body1["locked"]["shared"] == "1.0"  # 最小化：shared 保持当前版本


def test_upgrade_does_not_change_resolve_behavior():
    """同一快照上 /resolve 的输出不受 /upgrade 影响（无共享状态）。"""
    repo = {
        "app": [c("1.0", [d("libx"), d("liby")])],
        "libx": [c("1.0"), c("2.0")],
        "liby": [c("1.0"), c("2.0")],
    }
    resolve_body = {
        "repository": repo, "root": "app", "target_environment": ENV,
    }
    before = client.post("/resolve", json=resolve_body).json()
    upgrade(repo, {"app": "1.0", "libx": "1.0", "liby": "1.0"}, "libx")
    after = client.post("/resolve", json=resolve_body).json()
    assert before == after
    assert before["locked"] == {"app": "1.0", "libx": "2.0", "liby": "2.0"}
    assert "changes" not in before
