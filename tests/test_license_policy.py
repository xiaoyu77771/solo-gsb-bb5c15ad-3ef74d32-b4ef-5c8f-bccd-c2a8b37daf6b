"""POST /license-policy 的端到端测试。

覆盖：先审计后判定的 409 短路、SPDX AND/OR/括号表达式解析（优先级、
大小写不敏感运算符、非法表达式 422）、allow/deny 三态判定（标识精确
匹配、AND/OR 的 Kleene 语义）、缺失许可证归入 unknowns、最短路径附件
（菱形等长路径保留）、allow/deny 重叠 422、未锁定/未激活包的许可证
不参与判定、确定性排序，以及 422（非法快照/锁/根包/多余字段）。
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
WIN_ENV = {
    "python_version": "3.11",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}


def c(version, deps=None, license=None):
    entry = {"version": version, "dependencies": deps or []}
    if license is not None:
        entry["metadata"] = {"license": license}
    return entry


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def query(repo, lock, *, root="app", env=None, allow=None, deny=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "current_lock": lock,
        "allow": allow if allow is not None else ["MIT"],
        "deny": deny if deny is not None else ["GPL-3.0-only"],
    }
    body.update(overrides)
    return client.post("/license-policy", json=body)


def check(repo, lock, **kw):
    r = query(repo, lock, **kw)
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------- #
# 1. 基础：三态判定、按包名排序、路径附件
# --------------------------------------------------------------------- #
def test_basic_verdicts_sorted_with_paths():
    repo = {
        "app": [c("1.0", [d("ok-lib"), d("bad-lib"), d("mystery-lib")],
                  license="MIT")],
        "ok-lib": [c("1.0", license="MIT")],
        "bad-lib": [c("1.0", license="GPL-3.0-only")],
        "mystery-lib": [c("1.0", license="MPL-2.0")],
    }
    lock = {"app": "1.0", "ok-lib": "1.0", "bad-lib": "1.0",
            "mystery-lib": "1.0"}
    body = check(repo, lock)
    assert body["status"] == "ok"
    assert body["root"] == "app"
    # 允许的包（app、ok-lib）不出现在任何列表中。
    assert body["violations"] == [
        {"name": "bad-lib", "license": "GPL-3.0-only",
         "paths": [["app", "bad-lib"]]}
    ]
    assert body["unknowns"] == [
        {"name": "mystery-lib", "license": "MPL-2.0",
         "paths": [["app", "mystery-lib"]]}
    ]


def test_all_allowed_gives_empty_lists():
    repo = {"app": [c("1.0", [d("liba")], license="MIT")],
            "liba": [c("1.0", license="MIT")]}
    body = check(repo, {"app": "1.0", "liba": "1.0"})
    assert body["violations"] == [] and body["unknowns"] == []


def test_identifier_matching_is_exact_and_case_sensitive():
    """allow 中的 'mit' 不匹配表达式中的 'MIT'（精确匹配、大小写敏感）。"""
    repo = {"app": [c("1.0", license="MIT")]}
    body = check(repo, {"app": "1.0"}, allow=["mit"], deny=[])
    assert [i["name"] for i in body["unknowns"]] == ["app"]
    assert body["violations"] == []


def test_allow_entries_are_stripped_and_deduplicated():
    repo = {"app": [c("1.0", license="MIT")]}
    body = check(repo, {"app": "1.0"}, allow=[" MIT ", "MIT"], deny=[])
    assert body["unknowns"] == [] and body["violations"] == []


def test_empty_allow_and_deny_makes_everything_unknown():
    repo = {"app": [c("1.0", [d("liba")], license="MIT")],
            "liba": [c("1.0")]}  # liba 无许可证元数据
    body = check(repo, {"app": "1.0", "liba": "1.0"}, allow=[], deny=[])
    assert body["violations"] == []
    assert [i["name"] for i in body["unknowns"]] == ["app", "liba"]


# --------------------------------------------------------------------- #
# 2. AND / OR 的 Kleene 三态语义
# --------------------------------------------------------------------- #
def test_and_semantics():
    repo = {
        "app": [c("1.0", [d("all-ok"), d("has-deny"), d("has-unknown")],
                  license="MIT")],
        "all-ok": [c("1.0", license="MIT AND Apache-2.0")],
        "has-deny": [c("1.0", license="MIT AND GPL-3.0-only")],
        "has-unknown": [c("1.0", license="MIT AND MPL-2.0")],
    }
    lock = {"app": "1.0", "all-ok": "1.0", "has-deny": "1.0",
            "has-unknown": "1.0"}
    body = check(repo, lock, allow=["MIT", "Apache-2.0"],
                 deny=["GPL-3.0-only"])
    # AND：任一拒绝即违规（其余分支允许也不影响）。
    assert [i["name"] for i in body["violations"]] == ["has-deny"]
    # AND：允许 + 未知 -> 未知。
    assert [i["name"] for i in body["unknowns"]] == ["has-unknown"]


def test_or_semantics():
    repo = {
        "app": [c("1.0", [d("any-ok"), d("all-deny"), d("deny-unknown")],
                  license="MIT")],
        "any-ok": [c("1.0", license="GPL-3.0-only OR MIT")],
        "all-deny": [c("1.0", license="GPL-3.0-only OR AGPL-3.0-only")],
        "deny-unknown": [c("1.0", license="GPL-3.0-only OR MPL-2.0")],
    }
    lock = {"app": "1.0", "any-ok": "1.0", "all-deny": "1.0",
            "deny-unknown": "1.0"}
    body = check(repo, lock, allow=["MIT"],
                 deny=["GPL-3.0-only", "AGPL-3.0-only"])
    # OR：任一允许即通过（其余分支拒绝也不影响）；全部拒绝才违规。
    assert [i["name"] for i in body["violations"]] == ["all-deny"]
    # OR：拒绝 + 未知 -> 未知。
    assert [i["name"] for i in body["unknowns"]] == ["deny-unknown"]


def test_precedence_and_binds_tighter_than_or():
    """MIT OR GPL AND Apache == MIT OR (GPL AND Apache)：MIT 允许即通过。"""
    repo = {"app": [c("1.0", license="MIT OR GPL-3.0-only AND Apache-2.0")]}
    body = check(repo, {"app": "1.0"}, allow=["MIT"], deny=["GPL-3.0-only"])
    assert body["violations"] == [] and body["unknowns"] == []


def test_parentheses_override_precedence():
    """(MIT OR GPL) AND Apache：Apache 未知 -> 整体未知。"""
    repo = {"app": [c("1.0", license="(MIT OR GPL-3.0-only) AND Apache-2.0")]}
    body = check(repo, {"app": "1.0"}, allow=["MIT"], deny=["GPL-3.0-only"])
    assert [i["name"] for i in body["unknowns"]] == ["app"]
    assert body["violations"] == []


def test_nested_parentheses_and_case_insensitive_operators():
    repo = {
        "app": [c("1.0", license="(MIT or (BSD-3-Clause and Apache-2.0)) "
                                 "AnD LGPL-2.1-only")],
    }
    body = check(
        repo, {"app": "1.0"},
        allow=["MIT", "BSD-3-Clause", "Apache-2.0", "LGPL-2.1-only"],
        deny=[],
    )
    assert body["violations"] == [] and body["unknowns"] == []


def test_multi_way_or_all_denied_is_violation():
    repo = {"app": [c("1.0", license="GPL-2.0-only OR GPL-3.0-only OR AGPL-3.0-only")]}
    body = check(repo, {"app": "1.0"}, allow=[],
                 deny=["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only"])
    assert [i["name"] for i in body["violations"]] == ["app"]
    assert body["violations"][0]["paths"] == [["app"]]


# --------------------------------------------------------------------- #
# 3. 缺失许可证元数据 -> unknown（不阻断）
# --------------------------------------------------------------------- #
def test_missing_license_metadata_is_unknown_with_null():
    repo = {
        "app": [c("1.0", [d("liba")], license="MIT")],
        "liba": [c("1.0")],  # 无 metadata
    }
    body = check(repo, {"app": "1.0", "liba": "1.0"})
    assert body["unknowns"] == [
        {"name": "liba", "license": None, "paths": [["app", "liba"]]}
    ]


def test_empty_string_license_counts_as_missing():
    repo = {"app": [{"version": "1.0", "dependencies": [],
                     "metadata": {"license": "  "}}]}
    body = check(repo, {"app": "1.0"})
    assert body["unknowns"] == [
        {"name": "app", "license": None, "paths": [["app"]]}
    ]


# --------------------------------------------------------------------- #
# 4. 路径附件：根即目标、菱形等长路径、只保留最短
# --------------------------------------------------------------------- #
def test_root_violation_has_single_node_path():
    repo = {"app": [c("1.0", license="GPL-3.0-only")]}
    body = check(repo, {"app": "1.0"})
    assert body["violations"] == [
        {"name": "app", "license": "GPL-3.0-only", "paths": [["app"]]}
    ]


def test_diamond_target_keeps_all_equal_length_paths():
    repo = {
        "app": [c("1.0", [d("left"), d("right")])],
        "left": [c("1.0", [d("shared")])],
        "right": [c("1.0", [d("shared")])],
        "shared": [c("1.0", license="GPL-3.0-only")],
    }
    lock = {"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.0"}
    body = check(repo, lock)
    assert body["violations"][0]["paths"] == [
        ["app", "left", "shared"],
        ["app", "right", "shared"],
    ]


def test_only_shortest_paths_attached():
    repo = {
        "app": [c("1.0", [d("short"), d("long-arm")])],
        "short": [c("1.0", [d("bad")])],
        "long-arm": [c("1.0", [d("long-mid")])],
        "long-mid": [c("1.0", [d("bad")])],
        "bad": [c("1.0", license="GPL-3.0-only")],
    }
    lock = {"app": "1.0", "short": "1.0", "long-arm": "1.0",
            "long-mid": "1.0", "bad": "1.0"}
    body = check(repo, lock)
    assert body["violations"][0]["paths"] == [["app", "short", "bad"]]


# --------------------------------------------------------------------- #
# 5. 判定范围：仅锁定版本的许可证；未锁定/未激活包不参与
# --------------------------------------------------------------------- #
def test_license_taken_from_locked_candidate_only():
    repo = {
        "app": [c("1.0", [d("liba")], license="MIT")],
        "liba": [
            c("2.0", license="GPL-3.0-only"),  # 未锁定：不解析、不判定
            c("1.0", license="MIT"),
        ],
    }
    body = check(repo, {"app": "1.0", "liba": "1.0"})
    assert body["violations"] == [] and body["unknowns"] == []


def test_unlocked_package_with_invalid_spdx_does_not_422():
    """不在锁定清单中的包（含未激活 marker 依赖）的许可证不参与解析。"""
    repo = {
        "app": [c("1.0", [
            d("liba"),
            d("win-thing", marker="sys_platform == 'win32'"),
        ], license="MIT")],
        "liba": [c("1.0", license="MIT")],
        "win-thing": [c("1.0", license="not (a) license !!!")],
        "ghost": [c("1.0", license=")))")],
    }
    body = check(repo, {"app": "1.0", "liba": "1.0"}, env=ENV)
    assert body["violations"] == [] and body["unknowns"] == []


def test_inactive_marker_dependency_not_evaluated():
    repo = {
        "app": [c("1.0", [
            d("linux-thing", marker="sys_platform == 'linux'"),
            d("win-thing", marker="sys_platform == 'win32'"),
        ])],
        "linux-thing": [c("1.0", license="GPL-3.0-only")],
        "win-thing": [c("1.0", license="MIT")],
    }
    lock = {"app": "1.0", "linux-thing": "1.0"}
    body = check(repo, lock, env=ENV)
    assert [i["name"] for i in body["violations"]] == ["linux-thing"]
    # 同一把锁在 win32 下审计失败（extraneous/missing）-> 409，不判定。
    r = query(repo, lock, env=WIN_ENV)
    assert r.status_code == 409
    assert "violations" not in r.json()


def test_pep503_names_normalized_in_output():
    repo = {
        "Some_Root": [c("1.0", [d("DEP_X")], license="GPL-3.0-only")],
        "dep-x": [c("1.0", license="MPL-2.0")],
    }
    body = check(repo, {"some-root": "1.0", "dep-x": "1.0"}, root="Some_Root")
    assert body["root"] == "some-root"
    assert body["violations"] == [
        {"name": "some-root", "license": "GPL-3.0-only",
         "paths": [["some-root"]]}
    ]
    assert body["unknowns"] == [
        {"name": "dep-x", "license": "MPL-2.0",
         "paths": [["some-root", "dep-x"]]}
    ]


# --------------------------------------------------------------------- #
# 6. 确定性：与包键、锁键、allow/deny 顺序无关
# --------------------------------------------------------------------- #
def test_deterministic_across_input_ordering():
    repo = {
        "app": [c("1.0", [d("zz-top"), d("aa-first"), d("mm-mid")])],
        "zz-top": [c("1.0", [d("target")])],
        "aa-first": [c("1.0", [d("target")])],
        "mm-mid": [c("1.0", [d("target")])],
        "target": [c("1.0", license="GPL-3.0-only")],
    }
    lock = {"app": "1.0", "zz-top": "1.0", "aa-first": "1.0",
            "mm-mid": "1.0", "target": "1.0"}
    body1 = query(repo, lock, allow=["MIT", "Apache-2.0"],
                  deny=["GPL-3.0-only"]).json()
    body2 = query(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(lock.items()))),
        allow=["Apache-2.0", "MIT"],
        deny=["GPL-3.0-only"],
    ).json()
    assert body1 == body2
    assert body1["violations"][0]["paths"] == [
        ["app", "aa-first", "target"],
        ["app", "mm-mid", "target"],
        ["app", "zz-top", "target"],
    ]


# --------------------------------------------------------------------- #
# 7. 锁无效：409，携带与 /audit-lock 一致的问题，不判定
# --------------------------------------------------------------------- #
def test_invalid_lock_returns_409_with_audit_issues_and_no_verdicts():
    repo = {
        "app": [c("1.0", [d("needs-thing"), d("old-lib", ">=2.0")])],
        "old-lib": [c("1.0"), c("2.0")],
        "stale": [c("1.0")],
    }
    lock = {"app": "1.0", "old-lib": "1.0", "stale": "1.0"}
    r = query(repo, lock)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert [(i["type"], i["name"]) for i in body["issues"]] == [
        ("missing", "needs-thing"),
        ("constraint_mismatch", "old-lib"),
        ("extraneous", "stale"),
    ]
    assert "violations" not in body and "unknowns" not in body


def test_409_issues_match_audit_lock_endpoint():
    repo = {"app": [c("1.0", [d("libx")])], "libx": [c("1.0"), c("2.0")]}
    body = {"repository": repo, "root": "app", "target_environment": ENV,
            "current_lock": {"app": "1.0", "libx": "3.0"}}
    audit_body = client.post("/audit-lock", json=body).json()
    policy_body = query(repo, {"app": "1.0", "libx": "3.0"}).json()
    assert policy_body["issues"] == audit_body["issues"]


def test_invalid_lock_short_circuits_before_policy_checks():
    """锁无效时即使 allow/deny 重叠、许可证非法，也返回 409。"""
    repo = {
        "app": [c("1.0", [d("missing-lib")], license="not spdx !!")],
        "missing-lib": [c("1.0")],
    }
    r = query(repo, {"app": "1.0"}, allow=["MIT"], deny=["MIT"])
    assert r.status_code == 409
    assert r.json()["status"] == "invalid_lock"


# --------------------------------------------------------------------- #
# 8. allow/deny 重叠：422 invalid_policy
# --------------------------------------------------------------------- #
def test_overlapping_allow_deny_422():
    repo = {"app": [c("1.0", license="MIT")]}
    r = query(repo, {"app": "1.0"}, allow=["MIT", "BSD-3-Clause"],
              deny=["GPL-3.0-only", "MIT"])
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["status"] == "invalid_policy"
    assert "MIT" in body["message"] and "BSD-3-Clause" not in body["message"]


def test_overlap_message_lists_all_overlaps_sorted():
    repo = {"app": [c("1.0", license="MIT")]}
    r = query(repo, {"app": "1.0"}, allow=["Zlib", "MIT", "Apache-2.0"],
              deny=["MIT", "Zlib"])
    assert r.status_code == 422
    message = r.json()["message"]
    assert message.index("MIT") < message.index("Zlib")
    assert "Apache-2.0" not in message


def test_overlap_check_happens_before_spdx_parsing():
    """锁有效时，规则重叠优先于许可证解析报错。"""
    repo = {"app": [c("1.0", license="not spdx !!")]}
    r = query(repo, {"app": "1.0"}, allow=["MIT"], deny=["MIT"])
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_policy"


# --------------------------------------------------------------------- #
# 9. 非法 SPDX：422 invalid_license
# --------------------------------------------------------------------- #
def test_invalid_spdx_expressions_422():
    bad_licenses = [
        "MIT OR",            # 运算符后缺标识符
        "AND MIT",           # 运算符开头
        "(MIT",              # 括号未闭合
        "MIT)",              # 多余右括号
        "MIT GPL-2.0-only",  # 标识符之间缺运算符
        "()",                # 空括号
        "MIT WITH Classpath-exception-2.0",  # 不支持的 WITH
        "MIT/BSD-3-Clause",  # 非法字符
        "NOT MIT",           # 不支持的运算符
    ]
    for license_text in bad_licenses:
        repo = {"app": [c("1.0", license=license_text)]}
        r = query(repo, {"app": "1.0"})
        assert r.status_code == 422, (license_text, r.text)
        body = r.json()
        assert body["status"] == "invalid_license", license_text
        assert "app==1.0" in body["message"]
        assert license_text in body["message"]


def test_invalid_spdx_reported_in_package_name_order():
    """多个包许可证非法时，按规范化包名报第一个（确定性）。"""
    repo = {
        "app": [c("1.0", [d("bbb"), d("aaa")])],
        "bbb": [c("1.0", license="OR MIT")],
        "aaa": [c("1.0", license="MIT OR")],
    }
    r = query(repo, {"app": "1.0", "aaa": "1.0", "bbb": "1.0"})
    assert r.status_code == 422
    assert "'aaa==1.0'" in r.json()["message"]


def test_valid_spdx_identifier_forms_accepted():
    """GPL-2.0+、LicenseRef、单字符标识等合法形式都可解析。"""
    repo = {
        "app": [c("1.0", [d("liba"), d("libb"), d("libc")], license="MIT")],
        "liba": [c("1.0", license="GPL-2.0+")],
        "libb": [c("1.0", license="LicenseRef-Proprietary")],
        "libc": [c("1.0", license="X")],
    }
    lock = {"app": "1.0", "liba": "1.0", "libb": "1.0", "libc": "1.0"}
    body = check(repo, lock, allow=["GPL-2.0+", "X", "MIT"], deny=[])
    assert body["violations"] == []
    assert [i["name"] for i in body["unknowns"]] == ["libb"]


# --------------------------------------------------------------------- #
# 10. 422：非法快照 / 锁 / 根包 / 字段
# --------------------------------------------------------------------- #
def test_bad_snapshot_422():
    r = query({"app": [c("oops")]}, {"app": "1.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_bad_lock_version_422():
    r = query({"app": [c("1.0")]}, {"app": "not-a-version"})
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_unknown_root_422():
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, root="missing")
    assert r.status_code == 422
    assert "missing" in r.json()["message"]


def test_empty_allow_identifier_422():
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, allow=["  "])
    assert r.status_code == 422


def test_extra_top_level_field_forbidden_422():
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, unknown=1)
    assert r.status_code == 422


def test_allow_and_deny_optional():
    """allow/deny 均可缺省（默认空集合）。"""
    body = {
        "repository": {"app": [c("1.0", license="MIT")]},
        "root": "app",
        "target_environment": ENV,
        "current_lock": {"app": "1.0"},
    }
    r = client.post("/license-policy", json=body)
    assert r.status_code == 200, r.text
    assert [i["name"] for i in r.json()["unknowns"]] == ["app"]


def test_root_specifier_still_audited():
    """根约束不满足时锁审计失败 -> 409（沿用现有校验）。"""
    repo = {"app": [c("1.0", license="MIT"), c("2.0", license="MIT")]}
    r = query(repo, {"app": "1.0"}, specifier=">=2.0")
    assert r.status_code == 409
    assert r.json()["issues"][0]["type"] == "constraint_mismatch"
