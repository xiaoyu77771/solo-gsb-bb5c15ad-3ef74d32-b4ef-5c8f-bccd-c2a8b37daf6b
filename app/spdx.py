"""SPDX 许可证表达式解析与 allow/deny 三态判定（POST /license-policy）。

支持 SPDX 许可证表达式（SPDX 2.x / 3.x 语法）的一个确定性子集：
许可证**标识词**经 ``AND`` / ``OR`` 与括号任意组合。

词法规则：

* 原子标识词为标准 SPDX 标识（``MIT``、``BSD-3-Clause``、
  ``GPL-3.0-only``，允许单个尾随 ``+`` 的 "or later" 形式）或用户自定义
  引用 ``LicenseRef-<idstring>``（可带 ``DocumentRef-<idstring>:`` 前缀）；
  标识词**大小写敏感、按字面匹配**；
* ``AND`` / ``OR`` 是保留字，**大小写不敏感**，两侧必须是完整标识词或
  括号组，且必须以空白分隔（SPDX 语法）；``OR`` 优先级最低，``AND``
  更高，括号分组；
* 不支持 ``WITH`` 例外表达式（如
  ``GPL-2.0-only WITH Classpath-exception-2.0``），出现即按非法表达式
  处理（API 层映射为 422）。

三态判定：对每个原子标识词查 allow/deny 两个集合——在 ``deny`` 中为
``deny``、仅在 ``allow`` 中为 ``allow``、两者都不在为 ``unknown``；
复合表达式按三态逻辑组合：

* ``AND``：全部为 allow 才 allow；任一为 deny 即 deny；其余为 unknown；
* ``OR`` ：任一为 allow 即 allow；全部为 deny 才 deny；其余为 unknown。
"""

from __future__ import annotations

import re
from collections.abc import Collection

from .repository import SnapshotError

# 三态结果：deny < unknown < allow（数值仅用于内部比较，不直接对外）。
DENY = -1
UNKNOWN = 0
ALLOW = 1

# SPDX idstring：字母数字开头结尾，内部允许字母数字与 "."、"-"。
_IDSTRING = r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"

# 一个合法的原子标识词：标准标识（可尾随单个 "+"）或 LicenseRef 自定义引用。
_SPDX_LEAF_RE = re.compile(
    rf"(?:{_IDSTRING}\+?|LicenseRef-{_IDSTRING}"
    rf"|DocumentRef-{_IDSTRING}:LicenseRef-{_IDSTRING})"
)

# 词法扫描的记号：括号或“字母/数字/点开头，其后可含字母数字 . : + -”的词。
# 词本身是否为合法标识词由 _SPDX_LEAF_RE 在语法分析时判定（这样能给出
# 更准确的错误，如 LicenseRef 缺少 idstring）；"+"、"/" 等非法起始字符
# 在扫描期直接报错。
_TOKEN_RE = re.compile(r"[A-Za-z0-9.][A-Za-z0-9.:+-]*")

_MAX_TOKENS = 500  # 表达式记号上限：确定性防护，真实许可证表达式远小于此
_MAX_NESTING = 100  # 括号嵌套上限：同时保证递归求值不会撑爆调用栈


class LicenseExpressionError(ValueError):
    """许可证表达式不是合法的 SPDX AND/OR/括号表达式。"""


def _tokenize(text: str) -> list[str]:
    """把表达式文本切为记号；无法识别的字符抛 LicenseExpressionError。"""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch == "(" or ch == ")":
            tokens.append(ch)
            i += 1
        else:
            match = _TOKEN_RE.match(text, i)
            if match is None:
                raise LicenseExpressionError(
                    f"位置 {i} 处存在无法识别的字符 {ch!r}；SPDX 表达式只允许"
                    " 许可证标识、括号与空白分隔的 AND/OR"
                )
            tokens.append(match.group(0))
            i = match.end()
    return tokens


class _Parser:
    """递归下降解析器：文法为 or := and ('OR' and)*；
    and := atom ('AND' atom)*；atom := '(' or ')' | 标识词。
    """

    def __init__(self, tokens: list[str]):
        self._tokens = tokens
        self._pos = 0

    def peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def consume(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def parse_or(self, depth: int) -> tuple:
        left = self.parse_and(depth)
        while (tok := self.peek()) is not None:
            if tok.upper() == "OR":
                self.consume()
                left = ("or", left, self.parse_and(depth))
            elif tok.upper() == "WITH":
                raise LicenseExpressionError(
                    "不支持 WITH 许可证例外表达式（如 'GPL-2.0-only WITH"
                    " Classpath-exception-2.0'），只允许 AND/OR/括号组合"
                )
            else:
                break
        return left

    def parse_and(self, depth: int) -> tuple:
        left = self.parse_atom(depth)
        while (tok := self.peek()) is not None:
            if tok.upper() == "AND":
                self.consume()
                left = ("and", left, self.parse_atom(depth))
            elif tok.upper() == "WITH":
                raise LicenseExpressionError(
                    "不支持 WITH 许可证例外表达式（如 'GPL-2.0-only WITH"
                    " Classpath-exception-2.0'），只允许 AND/OR/括号组合"
                )
            else:
                break
        return left

    def parse_atom(self, depth: int) -> tuple:
        tok = self.peek()
        if tok is None:
            raise LicenseExpressionError("表达式提前结束：AND/OR 后缺少许可证标识")
        if tok == "(":
            self.consume()
            if depth + 1 > _MAX_NESTING:
                raise LicenseExpressionError(f"括号嵌套超过上限 {_MAX_NESTING} 层")
            inner = self.parse_or(depth + 1)
            if self.peek() != ")":
                raise LicenseExpressionError("括号未闭合：缺少匹配的 ')'")
            self.consume()
            return inner
        if tok == ")":
            raise LicenseExpressionError("存在多余的右括号 ')'")
        upper = tok.upper()
        if upper in ("AND", "OR", "WITH"):
            if upper == "WITH":
                raise LicenseExpressionError(
                    "不支持 WITH 许可证例外表达式（如 'GPL-2.0-only WITH"
                    " Classpath-exception-2.0'），只允许 AND/OR/括号组合"
                )
            raise LicenseExpressionError(
                f"意外的关键字 {tok!r}：AND/OR 两侧必须是许可证标识或括号组"
            )
        if _SPDX_LEAF_RE.fullmatch(tok) is None:
            raise LicenseExpressionError(
                f"{tok!r} 不是合法的 SPDX 许可证标识"
                "（标识以字母数字开头结尾，内部允许字母数字、'.'、'-'，"
                "或使用 LicenseRef-<id> / DocumentRef-<id>:LicenseRef-<id>）"
            )
        self.consume()
        return ("atom", tok)


def parse_spdx_expression(raw: str) -> tuple:
    """解析 SPDX AND/OR/括号表达式为 AST 元组；非法时抛 LicenseExpressionError。

    AST 节点形如 ``("atom", "MIT")``、``("and", left, right)``、
    ``("or", left, right)``；调用方一般使用 :func:`evaluate_spdx_expression`
    完成判定，AST 本身不对外暴露。
    """
    if raw is None or not raw.strip():
        raise LicenseExpressionError("空的 SPDX 许可证表达式")
    tokens = _tokenize(raw.strip())
    if not tokens:
        raise LicenseExpressionError("空的 SPDX 许可证表达式")
    if len(tokens) > _MAX_TOKENS:
        raise LicenseExpressionError(
            f"表达式记号数超过上限 {_MAX_TOKENS}"
        )
    parser = _Parser(tokens)
    node = parser.parse_or(0)
    leftover = parser.peek()
    if leftover is not None:
        if leftover == ")":
            raise LicenseExpressionError("存在多余的右括号 ')'")
        raise LicenseExpressionError(
            f"表达式在 {leftover!r} 附近缺少 AND/OR 连接"
            "（相邻标识词之间必须以 AND/OR 连接）"
        )
    return node


def evaluate_spdx_expression(
    node: tuple,
    allow: Collection[str],
    deny: Collection[str],
    *,
    depth: int = 0,
) -> int:
    """在给定 allow/deny 集合上对 AST 做三态求值，返回 ALLOW/DENY/UNKNOWN。

    原子标识按字面、大小写敏感地查集合：在 ``deny`` 中即拒绝，否则在
    ``allow`` 中为允许，两者都不在为未知。复合节点：

    * AND：任一拒绝即拒绝；全部允许才允许；其余未知；
    * OR ：任一允许即允许；全部拒绝才拒绝；其余未知。

    ``depth`` 为内部递归深度：解析期已把记号数限制在 _MAX_TOKENS、
    括号嵌套限制在 _MAX_NESTING，这里再做一次防御性检查，保证任何输入
    都不会撑爆调用栈。
    """
    if depth > _MAX_TOKENS:  # 理论不可达：解析器已严格限界
        raise LicenseExpressionError("表达式嵌套过深，无法求值")
    kind = node[0]
    if kind == "atom":
        identifier = node[1]
        if identifier in deny:
            return DENY
        if identifier in allow:
            return ALLOW
        return UNKNOWN

    left = evaluate_spdx_expression(
        node[1], allow, deny, depth=depth + 1
    )
    right = evaluate_spdx_expression(
        node[2], allow, deny, depth=depth + 1
    )
    if kind == "and":
        if left == DENY or right == DENY:
            return DENY
        if left == ALLOW and right == ALLOW:
            return ALLOW
        return UNKNOWN
    # kind == "or"
    if left == ALLOW or right == ALLOW:
        return ALLOW
    if left == DENY and right == DENY:
        return DENY
    return UNKNOWN


def is_valid_spdx_identifier(text: str) -> bool:
    """``text`` 是否为单个合法的 SPDX 原子标识词（用于校验 allow/deny）。

    AND/OR/WITH 是表达式语法保留字，即使拼写符合 idstring 形状也不能
    作为许可证标识。
    """
    if text.strip().upper() in ("AND", "OR", "WITH"):
        return False
    return bool(_SPDX_LEAF_RE.fullmatch(text))


def parse_policy_sets(
    allow: Collection[str], deny: Collection[str]
) -> tuple[set[str], set[str]]:
    """校验并规范化请求的 allow/deny 标识集合。

    每项去首尾空白后必须是合法的 SPDX 原子标识词（空串、含 AND/OR 等
    保留字、非法字符均拒绝）；同一集合内重复只保留一份。两个集合出现
    同一标识属于规则重叠——三态判定无法给出确定结论，抛 SnapshotError，
    由 API 层映射为 422。
    """

    def parse(values: Collection[str], field: str) -> set[str]:
        result: set[str] = set()
        for raw in values:
            text = (raw or "").strip()
            if not text:
                raise SnapshotError(f"{field} 中存在空的许可证标识")
            if not is_valid_spdx_identifier(text):
                raise SnapshotError(
                    f"{field} 中的标识 {raw!r} 不是合法的 SPDX 许可证标识"
                    "（只接受单个标识词，不接受 AND/OR/括号表达式；"
                    "自定义引用使用 LicenseRef-<id>）"
                )
            result.add(text)
        return result

    allow_set = parse(allow, "allow")
    deny_set = parse(deny, "deny")
    overlap = sorted(allow_set & deny_set)
    if overlap:
        raise SnapshotError(
            "allow 与 deny 包含重叠的许可证标识："
            + "、".join(overlap)
            + "；同一标识不得同时出现在两个集合中"
        )
    return allow_set, deny_set
