"""SPDX 许可证表达式解析与 allow/deny 三态判定（POST /license-policy）。

调用本模块前，请求的 ``current_lock`` 已由 :func:`app.audit.audit_lock`
判定为**有效**（与 /sbom、/dependency-paths 同一前置）。因此对锁定依赖图
（:func:`app.paths.build_locked_graph` 产出的根可达子图，节点集恰为锁中
全部包）中的每个包：

* ``metadata.license`` 缺失（快照未提供或为空串）→ 无法判定，归入
  ``unknowns``（与 /sbom 一样，缺失元数据不阻断）；
* 否则按 **SPDX 表达式**语法解析：许可证标识符 + ``AND`` / ``OR``
  （大小写不敏感）+ 括号；``OR`` 优先级低于 ``AND``。语法非法（含不支持的
  ``WITH`` 异常子句、多余字符、空括号等）抛
  :class:`LicenseExpressionError`，由 API 层映射为 422；
* 每个标识符按请求的 ``allow`` / ``deny`` 标识集合做**三态判定**
  （标识符与集合元素**精确匹配**，大小写敏感）：

  - 在 ``deny`` 中 → 拒绝；
  - 仅在 ``allow`` 中 → 允许；
  - 其余 → 未知。

* 表达式按 Kleene 三态逻辑求值：

  - ``AND``：任一分支拒绝 → 拒绝；全部分支允许 → 允许；其余 → 未知；
  - ``OR`` ：任一分支允许 → 允许；全部分支拒绝 → 拒绝；其余 → 未知。

判定为**拒绝**的包进入 ``violations``，**未知**的进入 ``unknowns``，
允许的包不再列出。两个列表都按规范化包名排序，每项附根包到该包的
**全部最短包路径**（复用 /dependency-paths 的 BFS，菱形等长路径全保留）。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import Version

from .audit import _find_candidate
from .paths import shortest_paths
from .repository import Repository

# 三态判定结果。
ALLOWED = "allowed"
DENIED = "denied"
UNKNOWN = "unknown"


class LicenseExpressionError(ValueError):
    """许可证文本不是合法的 SPDX AND/OR/括号表达式（API 层映射为 422）。"""


# --------------------------------------------------------------------- #
# 表达式 AST
# --------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Ident:
    name: str


@dataclass(frozen=True)
class _And:
    terms: tuple  # 两个及以上子表达式


@dataclass(frozen=True)
class _Or:
    options: tuple  # 两个及以上子表达式


# --------------------------------------------------------------------- #
# 词法分析：标识符 / AND / OR / 括号
# --------------------------------------------------------------------- #
# SPDX 标识符字符集：字母数字开头，可含 '.'、'-'、'+'（如 GPL-2.0+、
# LicenseRef-foo、Apache-2.0）。AND/OR 作为运算符保留（大小写不敏感），
# 不会出现在标识符位置。
_IDENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")


def _tokenize(text: str) -> list[tuple[str, str]]:
    """把许可证文本切分为 (类型, 原文) 词元序列；非法字符/运算符报错。"""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        ch = text[pos]
        if ch.isspace():
            pos += 1
            continue
        if ch == "(":
            tokens.append(("LPAREN", ch))
            pos += 1
            continue
        if ch == ")":
            tokens.append(("RPAREN", ch))
            pos += 1
            continue
        match = _IDENT_RE.match(text, pos)
        if match is None:
            raise LicenseExpressionError(f"无法识别的字符 {ch!r}")
        word = match.group(0)
        upper = word.upper()
        if upper == "AND":
            tokens.append(("AND", word))
        elif upper == "OR":
            tokens.append(("OR", word))
        elif upper == "WITH":
            raise LicenseExpressionError(
                "不支持的运算符 'WITH'（仅支持 AND/OR 与括号）"
            )
        else:
            tokens.append(("IDENT", word))
        pos = match.end()
    return tokens


# --------------------------------------------------------------------- #
# 语法分析（递归下降）：OR 优先级低于 AND
# --------------------------------------------------------------------- #
class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> tuple[str, str] | None:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def parse(self):
        node = self._parse_or()
        rest = self._peek()
        if rest is not None:
            raise LicenseExpressionError(
                f"期望 AND/OR 或表达式结束，但遇到 {rest[1]!r}"
            )
        return node

    def _parse_or(self):
        first = self._parse_and()
        options = [first]
        while (tok := self._peek()) is not None and tok[0] == "OR":
            self._pos += 1
            options.append(self._parse_and())
        return first if len(options) == 1 else _Or(tuple(options))

    def _parse_and(self):
        first = self._parse_unary()
        terms = [first]
        while (tok := self._peek()) is not None and tok[0] == "AND":
            self._pos += 1
            terms.append(self._parse_unary())
        return first if len(terms) == 1 else _And(tuple(terms))

    def _parse_unary(self):
        tok = self._peek()
        if tok is None:
            raise LicenseExpressionError("期望标识符或 '('，但表达式已结束")
        kind, text = tok
        if kind == "IDENT":
            self._pos += 1
            return _Ident(text)
        if kind == "LPAREN":
            self._pos += 1
            node = self._parse_or()
            closing = self._peek()
            if closing is None or closing[0] != "RPAREN":
                got = "表达式已结束" if closing is None else f"遇到 {closing[1]!r}"
                raise LicenseExpressionError(f"期望 ')'，但{got}")
            self._pos += 1
            return node
        raise LicenseExpressionError(f"期望标识符或 '('，但遇到 {text!r}")


def parse_license_expression(text: str, *, owner: str):
    """解析 SPDX AND/OR/括号表达式；非法时抛 LicenseExpressionError。

    ``owner`` 为出错时定位用的“包==版本”描述；错误信息带原始文本，
    同一输入的报错逐字节一致。
    """
    try:
        return _Parser(_tokenize(text)).parse()
    except LicenseExpressionError as exc:
        raise LicenseExpressionError(
            f"包 {owner!r} 的许可证表达式 {text!r} 不是合法的 SPDX 表达式: {exc}"
        ) from exc


# --------------------------------------------------------------------- #
# 三态求值
# --------------------------------------------------------------------- #
def _evaluate(node, allow: frozenset[str], deny: frozenset[str]) -> str:
    """Kleene 三态求值：AND 取最劣、OR 取最优（允许 > 未知 > 拒绝）。"""
    if isinstance(node, _Ident):
        if node.name in deny:
            return DENIED
        if node.name in allow:
            return ALLOWED
        return UNKNOWN
    if isinstance(node, _And):
        saw_unknown = False
        for term in node.terms:
            value = _evaluate(term, allow, deny)
            if value == DENIED:
                return DENIED
            if value == UNKNOWN:
                saw_unknown = True
        return UNKNOWN if saw_unknown else ALLOWED
    # _Or
    saw_unknown = False
    for option in node.options:
        value = _evaluate(option, allow, deny)
        if value == ALLOWED:
            return ALLOWED
        if value == UNKNOWN:
            saw_unknown = True
    return UNKNOWN if saw_unknown else DENIED


# --------------------------------------------------------------------- #
# 策略报告
# --------------------------------------------------------------------- #
def evaluate_license_policy(
    repo: Repository,
    *,
    root_name: str,
    current_lock: dict[str, Version],
    graph: dict[str, list[str]],
    allow: frozenset[str],
    deny: frozenset[str],
) -> dict:
    """对图中每个包（含根包）做许可证三态判定。

    前置条件：``current_lock`` 已通过审计——每个图节点都在锁中、锁定版本
    都在快照中。按包名升序遍历，因此返回的 ``violations`` / ``unknowns``
    天然按包名排序；每项附根包到该包的全部最短路径（已按字典序排序）。
    许可证文本非法时抛 :class:`LicenseExpressionError`（按包名序第一个
    非法者，确定性）。
    """
    violations: list[dict] = []
    unknowns: list[dict] = []

    for name in sorted(graph):
        locked = current_lock[name]  # 有效锁：图节点必有锁定版本
        cand = _find_candidate(repo, name, locked)  # 有效锁：锁定版本必在快照
        assert cand is not None
        license_text = cand.metadata.license

        if license_text is None:
            # 未提供许可证元数据：无法判定，归入未知（不阻断）。
            state = UNKNOWN
        else:
            expression = parse_license_expression(
                license_text, owner=f"{name}=={locked}"
            )
            state = _evaluate(expression, allow, deny)

        if state == ALLOWED:
            continue
        item = {
            "name": name,
            "license": license_text,
            "paths": shortest_paths(graph, root_name, name),
        }
        (violations if state == DENIED else unknowns).append(item)

    return {"violations": violations, "unknowns": unknowns}
