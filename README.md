# 本地依赖解析 API（Python · FastAPI · packaging）

一个完全本地化的软件依赖解析服务：仓库快照随请求提交，基于
[`packaging`](https://packaging.pypa.io/) 实现 PEP 440（版本/约束）、
PEP 503（包名规范化）与 **PEP 508（环境标记 marker）**，通过带回溯的
搜索生成**确定性锁定清单**；无解时返回从根需求到冲突包的**约束来源链**。
`/upgrade` 在现有锁定清单（`current_lock`）上升级单个目标包：取能完成
整体解析的最高版本，并最小化其余包相对当前锁的变更数量。
`/resolve-matrix` 把**同一份快照与根约束**提交给 **2～8 个带唯一 `id` 的
目标环境**：逐环境复用 `/resolve` 的全部规则求解，返回按 `id` 排序的各环境
锁定清单，以及按包名排序的跨环境版本矩阵（每个包记录各环境版本——未出现为
`null`——并标记 `shared` / `divergent`），用于快速定位跨平台锁定差异。
`/audit-lock` 对现有锁定清单做**只审计、不重新求解**的自洽性检查：按锁定
版本从根包遍历已激活依赖，报告缺失、版本不可用、约束不满足与多余的包。
`/dependency-paths` 在审计通过的锁定清单上**解释目标包为何出现**：按锁定
版本与目标环境激活的依赖建图，返回从根包到目标包的全部最短包路径
（菱形依赖保留等长路径，依赖环不重复节点、不会无限遍历）。
`/sbom` 同样**先审计 `current_lock`**，锁有效时沿已激活依赖图导出
**确定性 JSON 物料清单（SBOM）**：每个包给出规范化名称、版本、PURL
（Package URL）、依赖名称及候选版本随快照携带的 `source_url` / `sha256`
/ `license` 元数据；元数据缺失只形成 `warnings`，不阻断导出。

- **无远程访问**：不访问 PyPI 或任何索引，不做磁盘缓存，全部数据在请求内存中处理。
- **目标环境随请求给定**：每条依赖可携带 PEP 508 marker，由请求必填的
  `target_environment`（`python_version` / `sys_platform` / `platform_machine`）
  决定是否激活；**服务端不读取宿主机的任何平台信息**。
- **仅激活依赖参与求解**：marker 为假的依赖不进入全局约束、回溯、冲突来源链与 `edges`。
- **全局唯一版本**：同一包（PEP 503 规范化后）在整棵依赖树中只能选定一个版本。
- **高版本优先**：候选版本严格按 PEP 440 从高到低尝试，失败即回溯到更低版本。
- **最小变更升级**：`/upgrade` 只考虑严格高于当前版本的目标候选，取能完成
  整体解析的最高版本；该版本下在所有有效解中优先选择非目标包相对
  `current_lock` 新增/删除/版本变化数量最少的解。
- **环安全**：依赖环（含自环、菱形依赖）不会导致重复展开；环上的新约束仍会校验。
- **确定性**：结果只取决于快照内容与目标环境，与包键顺序、候选列表顺序无关。

---

## 一、单命令启动（Docker Compose）

```bash
docker compose up --build
```

服务启动后监听：

| 项目 | 地址 |
| --- | --- |
| API 根地址 | `http://localhost:8000` |
| 解析接口 | `POST http://localhost:8000/resolve` |
| 跨环境矩阵接口 | `POST http://localhost:8000/resolve-matrix` |
| 升级接口 | `POST http://localhost:8000/upgrade` |
| 审计接口 | `POST http://localhost:8000/audit-lock` |
| 依赖路径接口 | `POST http://localhost:8000/dependency-paths` |
| SBOM 导出接口 | `POST http://localhost:8000/sbom` |
| 健康检查 | `GET  http://localhost:8000/healthz` |
| 交互文档（Swagger） | `http://localhost:8000/docs` |
| OpenAPI Schema | `http://localhost:8000/openapi.json` |

端口在 `docker-compose.yml` 的 `ports: ["8000:8000"]` 中调整。

### 不使用 Docker 的本地运行方式

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 二、请求

### `POST /resolve`

请求体字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `repository` | `object` | 是 | 仓库快照：`{包名: [候选版本...]}`；包名按 PEP 503 规范化匹配（大小写/`_`/`.`/`-` 等价） |
| `repository.<pkg>[].version` | `string` | 是 | PEP 440 版本号，如 `1.2.3`、`2.0rc1` |
| `repository.<pkg>[].dependencies` | `array` | 否 | 该版本声明的依赖：`{"name", "specifier", "marker"}` |
| `repository.<pkg>[].metadata` | `object` | 否 | 该版本的可选 SBOM 元数据（仅 `/sbom` 使用）：`{"source_url", "sha256", "license"}`，三项均可缺省 |
| `…metadata[].source_url` | `string` | 否 | 该版本源码/分发包的绝对 URL（仅接受 `http`/`https`）；空串/缺省视为未提供 |
| `…metadata[].sha256` | `string` | 否 | 该版本分发包的 SHA-256 摘要（64 位十六进制字符，大小写接受、输出统一小写）；空串/缺省视为未提供 |
| `…metadata[].license` | `string` | 否 | 许可证标识（SPDX）或许可证文本；空串/缺省视为未提供 |
| `…dependencies[].name` | `string` | 是 | 被依赖包名（PEP 503 规范化匹配） |
| `…dependencies[].specifier` | `string` | 否 | PEP 440 版本约束，如 `>=1.0,<2.0`；空串表示不约束 |
| `…dependencies[].marker` | `string` | 否 | PEP 508 环境标记表达式（**不含**前导分号），如 `"sys_platform == 'linux'"`；空串表示无条件激活 |
| `root` | `string` | 是 | 根包名，必须存在于 `repository` |
| `target_environment` | `object` | 是 | marker 求值所用的目标环境，**三项全部必填**，值完全取自请求 |
| `target_environment.python_version` | `string` | 是 | 目标 Python 版本（PEP 440），如 `3.11`、`3.12.4` |
| `target_environment.sys_platform` | `string` | 是 | 目标操作系统（对应 `sys.platform`），如 `linux`、`win32`、`darwin` |
| `target_environment.platform_machine` | `string` | 是 | 目标 CPU 架构（对应 `platform.machine()`），如 `x86_64`、`aarch64`、`AMD64` |
| `specifier` | `string` | 否 | 对根包的 PEP 440 约束，如 `>=1.0,<2.0`；空串表示取最高版本 |
| `allow_prereleases` | `boolean` | 否 | 是否允许预发布（`a/b/rc/dev`），默认 `false`（pip 跟随语义：约束显式钉住预发布时仍可用） |

### PEP 508 marker 规则

- 每条依赖可选一个 `marker` 表达式，支持 `and` / `or` / 括号与比较
  （`==`、`!=`、`>=`、`>`、`<`、`<=`、`~=`、`in`、`not in`），例如：

  ```json
  {"name": "pywin32", "specifier": ">=300", "marker": "sys_platform == 'win32'"}
  ```

  ```json
  {"name": "arm-accel", "marker": "platform_machine == 'aarch64' and python_version >= '3.10'"}
  ```

- marker **只允许引用三个变量**：`python_version`、`sys_platform`、
  `platform_machine`。引用任何其它名称（`os_name`、`platform_system`、
  `python_full_version`、`implementation_name`、`extra` 等）都属于越界，
  返回 **422**；marker 语法非法同样返回 **422**。错误信息会定位到
  **包、版本与依赖**，形如：

  ```text
  包 'app==1.2.3' 对 'some-dep' 的依赖 的 marker 'python_version >>> 3.9' 不是合法的 PEP 508 标记: ...
  包 'app==1.0' 对 'x' 的依赖 的 marker 'os_name == "posix"' 引用了不允许的变量 'os_name'；仅允许引用：platform_machine、python_version、sys_platform
  ```

- 环境值**完全取自请求**：服务进程不会调用 `sys` / `platform` 探测宿主机，
  因此在 Linux 容器里提交 `sys_platform: "win32"` 的请求，会严格按
  Windows 环境求解。
- **只有求值为真的依赖激活**：未激活依赖不会进入全局约束、回溯搜索、
  冲突来源链（409 的 `constraints.chain`）与输出的 `edges`；即使它引用了
  不存在的包或无解版本，也完全不影响结果。
- marker 在解析前对快照一次性求值，同一输入（含 `target_environment`）
  的输出逐字节一致。
- 注意：marker 无论激活与否都会做语法与变量范围校验——非法 marker
  即使在该环境下不会生效，也仍然返回 422。

### 成功请求示例（含回溯）

```bash
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/resolve.json
```

`web-framework 3.1.0` 要求 `shared-util==2.0.0`，而 `auth-lib` 要求
`<2.0`，求解器回溯改选 `web-framework 2.4.0`：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "1.0.0",
  "locked": {
    "app": "1.0.0",
    "auth-lib": "0.9.0",
    "shared-util": "1.5.0",
    "web-framework": "2.4.0"
  },
  "edges": [
    {"from": "root", "to": "app", "specifier": "*"},
    {"from": "app==1.0.0", "to": "auth-lib", "specifier": "*"},
    {"from": "app==1.0.0", "to": "web-framework", "specifier": ">=2.0"},
    {"from": "auth-lib==0.9.0", "to": "shared-util", "specifier": "<2.0"},
    {"from": "web-framework==2.4.0", "to": "shared-util", "specifier": ">=1.0,<2.0"}
  ]
}
```

- `locked`：按规范化包名排序的**锁定清单**（包 → 全局唯一版本）。
- `edges`：按声明方/被依赖方排序的**依赖边**；空约束统一显示为 `*`，
  第一条恒为 `root → 根包`。

### 跨环境示例（同一快照，不同 `target_environment`）

同一份仓库快照中的 `app 2.0.0` 声明了按平台 / 架构 / Python 版本激活的
marker 依赖（`linux-helper`、`win-helper`、`speedlib`、`modern-core`、
`legacy-core`）。只改 `target_environment`，锁定结果随之不同：

```bash
# 目标：Linux x86_64 / Python 3.11
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/markers-linux.json

# 目标：Windows AMD64 / Python 3.9（同一快照，仅环境不同）
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/markers-windows.json
```

Linux 环境（`linux-helper` 拉入 `native-bindings==2`，激活 `speedlib`
与 `modern-core`；`win-helper`、`legacy-core` 未激活，不出现在结果中）：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "2.0.0",
  "locked": {
    "app": "2.0.0",
    "linux-helper": "1.2.0",
    "modern-core": "4.0.0",
    "native-bindings": "2",
    "speedlib": "1.0.0"
  },
  "edges": [
    {"from": "root", "to": "app", "specifier": "*"},
    {"from": "app==2.0.0", "to": "linux-helper", "specifier": ">=1.0"},
    {"from": "app==2.0.0", "to": "modern-core", "specifier": "*"},
    {"from": "app==2.0.0", "to": "speedlib", "specifier": "*"},
    {"from": "linux-helper==1.2.0", "to": "native-bindings", "specifier": "==2"}
  ]
}
```

Windows 环境（`win-helper` 拉入 `native-bindings==1`，激活
`legacy-core`；`speedlib` 要求 `x86_64` 而未激活）：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "2.0.0",
  "locked": {
    "app": "2.0.0",
    "legacy-core": "0.9.0",
    "native-bindings": "1",
    "win-helper": "1.2.0"
  },
  "edges": [
    {"from": "root", "to": "app", "specifier": "*"},
    {"from": "app==2.0.0", "to": "legacy-core", "specifier": "*"},
    {"from": "app==2.0.0", "to": "win-helper", "specifier": ">=1.0"},
    {"from": "win-helper==1.2.0", "to": "native-bindings", "specifier": "==1"}
  ]
}
```

即使请求运行在 Linux 容器中，第二次请求仍严格按 `win32` / `AMD64` /
`3.9` 求解——环境值不会回退到宿主机。

### 无解请求示例（返回约束来源链）

```bash
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/conflict.json
```

`left` 与 `right` 对 `core` 给出互斥钉死约束，返回 `409`：

```json
{
  "status": "conflict",
  "message": "依赖约束无解，冲突包：core",
  "conflicts": [
    {
      "subject": "core",
      "kind": "incompatible",
      "message": "已选 core==1.0 与约束交集 ==1.0,==2.0 不兼容",
      "constraints": [
        {"chain": [
          {"package": null, "version": null, "requires": "*"},
          {"package": "app", "version": "1.0.0", "requires": "*"},
          {"package": "left", "version": "1.0", "requires": "==1.0"}
        ]},
        {"chain": [
          {"package": null, "version": null, "requires": "*"},
          {"package": "app", "version": "1.0.0", "requires": "*"},
          {"package": "right", "version": "1.0", "requires": "==2.0"}
        ]}
      ],
      "partial_selection": {"app": "1.0.0", "core": "1.0", "left": "1.0", "right": "1.0"}
    }
  ]
}
```

每条 `chain` 都是一跳约束来源：`package=null` 表示请求本身（根需求），
其后每一跳表示“`<package>==<version>` 声明了 `requires`”。同一冲突包上
所有互斥约束的来源链都会列出（回溯中尝试过的候选版本同样会出现）。

`kind` 取值：

- `no_candidates`：约束交集下没有任何候选版本（或该包不在快照中）；
- `incompatible`：包已选定版本后，环/菱形路径带来了不兼容约束。

### 其他状态码

| 状态码 | 含义 |
| --- | --- |
| `200` | 解析成功 |
| `409` | 约束无解（`status: "conflict"`）；或搜索超过内置尝试上限（`status: "limit"`） |
| `422` | 请求/快照非法：非 PEP 440 版本、非法约束串、**marker 语法非法或引用越界变量**、`target_environment` 缺失/字段非法、根包不在快照中、字段校验失败等 |

`GET /healthz` 返回 `{"status":"ok"}`。

### `POST /resolve-matrix`

同一份仓库快照与根约束，一次提交给 **2～8 个目标环境**分别求解，直接得到
跨平台锁定差异。请求体沿用 `/resolve` 的 `repository` / `root` /
`specifier` / `allow_prereleases`（语义完全一致），只把单个
`target_environment` 换成带唯一 `id` 的 `target_environments` 列表：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target_environments` | `array` | 是 | **2～8 个**目标环境；少于 2 个或多于 8 个返回 422 |
| `target_environments[].id` | `string` | 是 | 环境标识（PEP 503 包名字符集：字母数字与 `._-`，首尾为字母/数字）；同一次请求内**必须唯一**，重复返回 422 |
| `target_environments[].python_version` | `string` | 是 | 同 `/resolve` 的 `target_environment.python_version` |
| `target_environments[].sys_platform` | `string` | 是 | 同上 |
| `target_environments[].platform_machine` | `string` | 是 | 同上 |

每个环境**独立复用 `/resolve` 的全部求解规则**（marker 激活、MRV/回溯、
预发布跟随语义、尝试上限），互不影响。快照与根约束只校验一次。

```bash
curl -s -X POST http://localhost:8000/resolve-matrix \
  -H 'Content-Type: application/json' \
  -d @examples/resolve-matrix.json
```

示例把前述跨平台快照提交给三个环境（Linux x86_64 / Windows AMD64 /
Linux aarch64）。**全部环境有解时返回 200**：`results` 是各环境的
`root_version` 与 `locked`，**按 `id` 排序**；`matrix` 是跨环境版本矩阵，
**按包名排序**——每行给出该包在每个环境的版本（未出现在该环境锁定清单中
为 `null`），并标记：

- `"shared"`：每个环境都锁定了该包且版本完全相同；
- `"divergent"`：版本不同，或该包只出现在部分环境（对应 `versions` 中的 `null`）。

```json
{
  "status": "ok",
  "root": "app",
  "results": [
    {
      "id": "linux-arm64-py311",
      "root_version": "2.0.0",
      "locked": {
        "app": "2.0.0",
        "linux-helper": "1.2.0",
        "modern-core": "4.0.0",
        "native-bindings": "2"
      }
    },
    {
      "id": "linux-x64-py311",
      "root_version": "2.0.0",
      "locked": {
        "app": "2.0.0",
        "linux-helper": "1.2.0",
        "modern-core": "4.0.0",
        "native-bindings": "2",
        "speedlib": "1.0.0"
      }
    },
    {
      "id": "win-amd64-py39",
      "root_version": "2.0.0",
      "locked": {
        "app": "2.0.0",
        "legacy-core": "0.9.0",
        "native-bindings": "1",
        "win-helper": "1.2.0"
      }
    }
  ],
  "matrix": [
    {
      "name": "app",
      "versions": {"linux-arm64-py311": "2.0.0", "linux-x64-py311": "2.0.0", "win-amd64-py39": "2.0.0"},
      "state": "shared"
    },
    {
      "name": "native-bindings",
      "versions": {"linux-arm64-py311": "2", "linux-x64-py311": "2", "win-amd64-py39": "1"},
      "state": "divergent"
    },
    {
      "name": "speedlib",
      "versions": {"linux-arm64-py311": null, "linux-x64-py311": "1.0.0", "win-amd64-py39": null},
      "state": "divergent"
    }
  ]
}
```

（为节省篇幅，上例 `matrix` 只展开了三行；实际响应包含全部出现在任一环境
锁定清单中的包。）由矩阵可直接读出：根包三环境一致（`shared`）；
`native-bindings` 在 Windows 被锁到 `1`、Linux 锁到 `2`（版本差异型
`divergent`）；`speedlib` 只在 x86_64 激活（缺失型 `divergent`，缺失列为
`null`）。根包本身也是矩阵的一行：环境相关的回溯可能让某些环境改选更低的
根版本，此时该根包行同样为 `divergent`，各环境实际锁定的根版本以
`results[].root_version` 为准。

**任一环境无解时整体返回 409**（即使其他环境有解），服务端仍会跑完全部
环境，`failures` 按 `id` 排序列出**各失败环境的原冲突结果**——内容与对该
环境单独调用 `/resolve` 得到的 409 完全一致（`status` / `message` /
`conflicts` 约束来源链）：

```bash
curl -s -X POST http://localhost:8000/resolve-matrix \
  -H 'Content-Type: application/json' \
  -d @examples/resolve-matrix-conflict.json
```

```json
{
  "status": "conflict",
  "message": "1 个目标环境无解（共 2 个）：win-amd64",
  "failures": [
    {
      "id": "win-amd64",
      "status": "conflict",
      "message": "依赖约束无解，冲突包：core",
      "conflicts": [
        {
          "subject": "core",
          "kind": "incompatible",
          "message": "已选 core==1.0 与约束交集 ==1.0,==2.0 不兼容",
          "constraints": [
            {"chain": [
              {"package": null, "version": null, "requires": "*"},
              {"package": "app", "version": "1.0.0", "requires": "*"},
              {"package": "left", "version": "1.0", "requires": "==1.0"}
            ]},
            {"chain": [
              {"package": null, "version": null, "requires": "*"},
              {"package": "app", "version": "1.0.0", "requires": "*"},
              {"package": "right", "version": "1.0", "requires": "==2.0"}
            ]}
          ],
          "partial_selection": {"app": "1.0.0", "core": "1.0", "left": "1.0", "right": "1.0"}
        }
      ]
    }
  ]
}
```

上例中 `left → core==1.0` 无条件激活，而 `right → core==2.0` 只在
`win32` 激活：Linux 环境正常锁定，Windows 环境互斥冲突，因此整体 409 且
`failures` 只含 `win-amd64`（409 响应不返回成功环境的锁定清单）。

`/resolve-matrix` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 全部环境求解成功，返回按 `id` 排序的 `results`（各含 `root_version` 与 `locked`）与按包名排序的 `matrix` |
| `409` | 至少一个环境无解或超过搜索上限：`status: "conflict"`，`failures` 按 `id` 排序列出各失败环境的原冲突结果（单环境的 `status` 也可能为 `"limit"`） |
| `422` | 请求/快照非法（同 `/resolve`），或环境数量不在 2～8、`id` 非法、**`id` 重复** |

### `POST /upgrade`

在现有锁定清单上升级**单个目标包**。请求体包含 `/resolve` 的全部字段
（`repository` / `root` / `target_environment` / `specifier` /
`allow_prereleases`，语义完全一致），并附加两个字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `current_lock` | `object` | 是 | 当前锁定清单：`{包名: 版本}`；包名按 PEP 503 规范化匹配，版本须为合法 PEP 440。仅作为最小化变更的参照，不参与约束求解 |
| `target` | `string` | 是 | 要升级的包名；**必须存在于 `current_lock` 中**，否则返回 422 |

升级规则：

1. 只考虑 `target` **严格高于** `current_lock[target]` 的候选版本
   （预发布版本遵循 `allow_prereleases`，与 `/resolve` 相同）；
2. 从高到低尝试候选：以根级 `==版本` 约束钉住目标包后做整体解析，
   **第一个存在可行解的候选即为目标版本**；所有更高候选均无解
   （或根本没有更高版本）时返回 **409**；
3. 目标版本确定后，在该版本的**所有有效解**中，优先选择非目标包相对
   `current_lock` 的**新增 + 删除 + 版本变化数量最少**的解；数量相同时
   沿用 `/resolve` 的确定性版本顺序（高版本优先）；
4. `current_lock` 不约束求解：未出现在新锁定清单中的包记为删除，
   新引入的包记为新增，版本按 PEP 440 比较（`1.0` 与 `1.0.0` 相等，
   不产生变更项）。

```bash
curl -s -X POST http://localhost:8000/upgrade \
  -H 'Content-Type: application/json' \
  -d @examples/upgrade.json
```

示例中 `web-framework` 当前锁定 `2.4.0`：候选 `3.1.0` 要求
`shared-util==2.0.0`，与 `auth-lib` 的 `<2.0` 冲突而被跳过；`3.2.0`
是可行的最高目标版本，且 `shared-util` 保持 `current_lock` 中的
`1.5.0`（变更数最少）：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "1.0.0",
  "locked": {
    "app": "1.0.0",
    "auth-lib": "0.9.0",
    "shared-util": "1.5.0",
    "web-framework": "3.2.0"
  },
  "changes": [
    {"name": "web-framework", "from": "2.4.0", "to": "3.2.0"}
  ]
}
```

- `locked`：升级后的**完整**锁定清单（按规范化包名排序）。
- `changes`：相对 `current_lock` 的全部变化（含目标包），**按包名排序**；
  `from` 为 `null` 表示新增包，`to` 为 `null` 表示被删除的包。

`/upgrade` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 升级成功，返回完整 `locked` 与 `changes` |
| `409` | 无可行升级（没有严格更高的候选，或所有更高候选都无法完成整体解析，`status: "conflict"` 并附冲突来源链）；或搜索超过内置尝试上限（`status: "limit"`） |
| `422` | 请求/快照非法（同 `/resolve`），或 `target` 不存在于 `current_lock` 中、`current_lock` 含非法 PEP 440 版本 |

### `POST /audit-lock`

对一份**现有锁定清单**做自洽性审计。请求体包含 `/resolve` 的全部字段
（`repository` / `root` / `target_environment` / `specifier` /
`allow_prereleases`，语义完全一致），并附加 `current_lock`（与 `/upgrade`
同名同格式）：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `current_lock` | `object` | 是 | 被审计的锁定清单：`{包名: 版本}`；包名按 PEP 503 规范化匹配，版本须为合法 PEP 440 |

**审计不重新求解、不选择任何版本**——版本完全由 `current_lock` 给定：

1. 从根包的锁定版本出发，按目标环境展开该版本声明的**已激活**依赖
   （marker 语义与 `/resolve` 完全一致：未激活的依赖不参与审计）；
2. 依赖环 / 菱形中同一个包**只展开一次**，但指向它的**每一条入边约束
   都累计核对**（环上回边的约束同样参与）；
3. 包名按 PEP 503 规范化匹配（`Some_Pkg` ≡ `some-pkg`），版本按 PEP 440
   等价性判断（锁中的 `1.0` 与快照中的 `1.0.0` 视为同一版本，`==1.0`
   同样满足）；约束满足判断与求解器共用同一套 pip 预发布跟随语义。

每个有问题的包产出一条 `issue`，类型固定为以下四种：

| `type` | 含义 |
| --- | --- |
| `missing` | 该包按锁定版本的依赖图**可达**，却未出现在 `current_lock` 中（`locked_version` 为 `null`） |
| `unavailable` | 锁定版本**不在仓库快照**中（或包完全不在快照中，`available` 为空） |
| `constraint_mismatch` | 锁定版本**不满足根约束或任一入边依赖约束**；`constraints` 只列未满足的约束，逐条带 `"satisfies": false` |
| `extraneous` | 锁中存在但从根包按锁定版本**不可达**的包（含仅被未激活 marker 依赖要求的包）；`constraints` 恒为空 |

每条 `issue` 包含：

| 字段 | 说明 |
| --- | --- |
| `type` | 上述四种类型之一 |
| `name` | 规范化包名（PEP 503） |
| `locked_version` | 锁中版本；`missing` 时为 `null` |
| `available` | 快照中该包的全部可用版本（PEP 440 降序）；包不在快照中时为 `[]` |
| `constraints` | 累计到该包的入边约束（含根约束，已去重并按来源排序）：每条含 `from`（`root` 或 `pkg==version`）、`specifier`（空约束显示 `*`）；仅 `constraint_mismatch` 的条目额外带 `satisfies`（恒为 `false`） |

无任何问题时返回 `"valid": true` 且 `issues` 为空。`issues` **确定性排序**：
先按类型（`missing` → `unavailable` → `constraint_mismatch` →
`extraneous`），同类型内按规范化包名；与包键 / 候选列表的输入顺序无关。

```bash
curl -s -X POST http://localhost:8000/audit-lock \
  -H 'Content-Type: application/json' \
  -d @examples/audit-lock.json
```

示例快照里：`monitoring-lib` 被依赖却未锁定（missing）、`web-framework`
锁了快照中不存在的 `3.3.0`（unavailable）、`cache-lib` 锁 `1.5.0` 不满足
`>=2.0`（constraint_mismatch）、`stale-pkg` 完全不可达（extraneous），
而 `win-only` 仅在 `sys_platform == 'win32'` 激活、linux 请求下不可达
（extraneous）：

```json
{
  "status": "ok",
  "valid": false,
  "issues": [
    {
      "type": "missing",
      "name": "monitoring-lib",
      "locked_version": null,
      "available": ["1.0.0"],
      "constraints": [
        {"from": "app==1.0.0", "specifier": ">=1.0"}
      ]
    },
    {
      "type": "unavailable",
      "name": "web-framework",
      "locked_version": "3.3.0",
      "available": ["3.2.0", "2.4.0"],
      "constraints": [
        {"from": "app==1.0.0", "specifier": ">=2.0"}
      ]
    },
    {
      "type": "constraint_mismatch",
      "name": "cache-lib",
      "locked_version": "1.5.0",
      "available": ["2.0.0", "1.5.0"],
      "constraints": [
        {"from": "app==1.0.0", "specifier": ">=2.0", "satisfies": false}
      ]
    },
    {
      "type": "extraneous",
      "name": "stale-pkg",
      "locked_version": "0.1.0",
      "available": [],
      "constraints": []
    },
    {
      "type": "extraneous",
      "name": "win-only",
      "locked_version": "1.0",
      "available": ["1.0"],
      "constraints": []
    }
  ]
}
```

遍历细节：

- `missing` / `unavailable` 是**遍历断点**——锁中没有该包、或锁定版本不在
  快照时，无法得知它的依赖声明，因此不沿其继续展开；只经这些断点才可到达
  的锁中包会报 `extraneous`。
- `constraint_mismatch` **不阻断遍历**：锁定版本仍在快照中，其声明的依赖
  照常展开（一份锁可以同时有约束不满足和下游缺包）。
- marker 无论激活与否都做语法与变量范围校验，非法 marker 仍返回 **422**
  （与 `/resolve` 一致）；只有求值为真的依赖进入遍历。

`/audit-lock` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 审计完成（`valid` 为 `true` 或 `false` 都是 200；审计不产生 409） |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本 |

### `POST /dependency-paths`

解释**目标包为何出现在锁定清单中**。请求体沿用 `/audit-lock` 的全部字段
（`/resolve` 字段 + `current_lock`），并附加一个 `target`：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `current_lock` | `object` | 是 | 被解释的锁定清单：`{包名: 版本}`，格式同 `/audit-lock` |
| `target` | `string` | 是 | 要解释的目标包名（PEP 503 规范化匹配）；目标为根包时返回单节点路径，不在锁中/不可达时返回 `reachable: false` |

处理流程：

1. **先按 `/audit-lock` 的同一套规则校验 `current_lock`**（含目标环境的
   marker 激活语义）。锁无效时返回 **409**，携带与 `/audit-lock` 逐字节
   一致、确定性排序的 `issues`，**不执行任何路径查询**（响应中没有
   `paths` / `reachable` 字段）；
2. 锁有效时，**不做任何版本选择**：按每个包的**锁定版本**展开它在目标
   环境下的已激活依赖构成有向图（未激活 marker 依赖不是图的边）；
   同一对包之间的多条依赖声明（不同约束文本）只产生一条边；
3. 从根包做无权 BFS，返回到**规范化目标名**的**所有最短包路径**：
   - **菱形依赖**产生的等长路径全部保留（路径数为各分叉的组合数）；
     更长的路径不返回；
   - **依赖环**（含自环）安全：每个包只展开一次，BFS 只记录最短距离上的
     前驱，路径内不重复节点，也不会无限遍历；
   - 目标即根包时返回唯一的单节点路径 `[根包]`；
   - 目标不在锁定清单或从根包不可达时返回 `"reachable": false` 与
     `"paths": []`（在有效锁上，锁中包都从根可达，因此不可达通常意味着
     目标根本不在锁中）。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` / `target` | 规范化（PEP 503）后的根包名与目标包名 |
| `reachable` | 目标是否可达；`false` 时 `paths` 恒为空 |
| `paths` | 最短包路径列表；每条路径是规范化包名序列（**含根节点与目标节点**，路径内为访问次序、不重排）；全部路径按字典序**确定性排序**，与包键/依赖声明/锁键的输入顺序无关 |

```bash
curl -s -X POST http://localhost:8000/dependency-paths \
  -H 'Content-Type: application/json' \
  -d @examples/dependency-paths.json
```

示例锁中 `shared-util 1.5.0` 同时被 `web-framework 3.2.0`
（`>=1.0,<3.0`）与 `auth-lib 0.9.0`（`<2.0`）要求，构成菱形，两条等长
路径都返回（字典序 `auth-lib` 在 `web-framework` 之前）：

```json
{
  "status": "ok",
  "root": "app",
  "target": "shared-util",
  "reachable": true,
  "paths": [
    ["app", "auth-lib", "shared-util"],
    ["app", "web-framework", "shared-util"]
  ]
}
```

目标不在锁定清单中（或不可达）时：

```json
{
  "status": "ok",
  "root": "app",
  "target": "nope",
  "reachable": false,
  "paths": []
}
```

`/dependency-paths` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 锁有效，路径查询完成（`reachable` 为 `true` 或 `false` 都是 200） |
| `409` | 锁定清单未通过审计：`status: "invalid_lock"`，`issues` 与 `/audit-lock` 的输出一致（确定性排序），不执行路径查询 |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本、`target` 名称非法 |

### `POST /sbom`

在**审计通过的锁定清单**上导出确定性 JSON 物料清单（SBOM）。请求体沿用
`/audit-lock` 的全部字段（`/resolve` 字段 + `current_lock`，语义完全
一致），无额外字段；候选版本可携带的 `source_url` / `sha256` /
`license` 元数据定义在 `repository` 的候选条目上（见上文 `/resolve`
字段表）。

处理流程：

1. **先按 `/audit-lock` 的同一套规则校验 `current_lock`**（含目标环境的
   marker 激活语义）。锁无效时返回 **409**，携带与 `/audit-lock`
   逐字节一致、确定性排序的 `issues`，**不导出任何清单**（响应中没有
   `packages` / `warnings` 字段）；
2. 锁有效时**不做任何版本选择**：按每个包的**锁定版本**沿目标环境下的
   **已激活依赖图**展开（与 `/dependency-paths` 同一张图；未激活 marker
   依赖既不是图的边，也不是导出的包）；
3. 逐包导出清单条目；**元数据缺失不阻断导出**——只在顶层 `warnings`
   中逐项提示。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` | 规范化（PEP 503）后的根包名 |
| `packages` | 已激活依赖图中的全部包（**含根包**），**按规范化包名排序** |
| `packages[].name` | PEP 503 规范化包名 |
| `packages[].version` | 锁定版本（PEP 440 字符串） |
| `packages[].purl` | [Package URL](https://github.com/package-url/purl-spec)：`pkg:pypi/<规范化名>@<版本>`；版本按 PURL 规则做确定性最小百分号编码（PEP 440 的 `1.0`、`2.0rc1`、`1!2.0` 等均原样输出） |
| `packages[].dependencies` | 该包锁定版本声明的**已激活**依赖的规范化名称：同一依赖的多条声明去重、按名称排序；未激活 marker 依赖不出现；无依赖时为 `[]` |
| `packages[].metadata` | 候选版本携带的元数据：`source_url` / `sha256` / `license`；快照未提供的字段为 `null`（sha256 输出统一小写） |
| `warnings` | 元数据缺失提示，**按包名排序**；仅列出至少缺一个字段的包。每条为 `{"name", "missing"}`，`missing` 是缺失字段名列表，按固定枚举次序 `license` → `sha256` → `source_url` 排列；元数据完整时 `warnings` 为 `[]` |

```bash
curl -s -X POST http://localhost:8000/sbom \
  -H 'Content-Type: application/json' \
  -d @examples/sbom.json
```

示例中四个包均锁定且元数据完整度不一：`app` / `web-framework` 三项齐全，
`auth-lib` 缺 `sha256`，`shared-util 1.5.0` 缺 `source_url`
（快照中存在但未锁定的 `shared-util 2.0.0` / `web-framework 2.4.0`
的元数据不会出现——元数据取自**锁定版本**的候选）：

```json
{
  "status": "ok",
  "root": "app",
  "packages": [
    {
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:pypi/app@1.0.0",
      "dependencies": ["auth-lib", "web-framework"],
      "metadata": {
        "source_url": "https://example.invalid/src/app-1.0.0.tar.gz",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "license": "Apache-2.0"
      }
    },
    {
      "name": "auth-lib",
      "version": "0.9.0",
      "purl": "pkg:pypi/auth-lib@0.9.0",
      "dependencies": ["shared-util"],
      "metadata": {
        "source_url": "https://example.invalid/src/auth-lib-0.9.0.tar.gz",
        "sha256": null,
        "license": "MIT"
      }
    },
    {
      "name": "shared-util",
      "version": "1.5.0",
      "purl": "pkg:pypi/shared-util@1.5.0",
      "dependencies": [],
      "metadata": {
        "source_url": null,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "license": "MIT"
      }
    },
    {
      "name": "web-framework",
      "version": "3.2.0",
      "purl": "pkg:pypi/web-framework@3.2.0",
      "dependencies": ["shared-util"],
      "metadata": {
        "source_url": "https://example.invalid/src/web-framework-3.2.0.tar.gz",
        "sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "license": "BSD-3-Clause"
      }
    }
  ],
  "warnings": [
    {"name": "auth-lib", "missing": ["sha256"]},
    {"name": "shared-util", "missing": ["source_url"]}
  ]
}
```

遍历与确定性细节：

- 元数据**只读取锁定版本的候选**：同一包未被锁定的其他版本携带的元数据
  不会导出，也不会与锁定版本合并。
- 同一包名（PEP 503）同一版本在快照中出现多次时，依赖声明与元数据都必须
  完全一致，否则返回 422；完全重复则合并为一条候选。
- `dependencies` 与 `packages` 都按规范化名排序，`warnings` 按包名排序；
  重复请求同一快照、锁与环境，输出逐字节一致。
- 未激活 marker 依赖不参与：换一个 `target_environment`，已激活图变化，
  导出的包与依赖名随之变化（在新环境下若锁审计失败则返回 409）。

`/sbom` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 锁有效，SBOM 导出完成（即使存在元数据 `warnings` 仍是 200） |
| `409` | 锁定清单未通过审计：`status: "invalid_lock"`，`issues` 与 `/audit-lock` 的输出一致（确定性排序），不导出清单 |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本、候选 `metadata.sha256` 不是 64 位十六进制、`metadata.source_url` 不是 `http`/`https` 绝对 URL |

---

## 三、解析规则说明

1. **包名规范化**：统一使用 PEP 503（`Some_Pkg`、`some.pkg`、`some-pkg` 视为同一个包）。
2. **环境标记（PEP 508）**：每条依赖的 `marker` 在请求提供的
   `target_environment` 上求值；只允许引用 `python_version` /
   `sys_platform` / `platform_machine`，求值环境不读取宿主机。仅激活的
   依赖进入后续全部求解流程（约束收集、回溯、来源链、`edges`）。
3. **约束交集**：对每个包收集所有激活的传递路径上的 PEP 440 约束，必须同时满足。
4. **选择次序**：在所有未决包中优先展开“可满足候选最少”的包（MRV），
   名称次序兜底；具体候选严格从高版本到低版本尝试。
5. **回溯**：候选版本展开后若与后续传递依赖冲突，放弃该版本，尝试下一个更低版本；
   每次尝试在独立的状态克隆上进行，失败不会污染其他分支。
6. **环处理**：已选定的包被再次要求时只校验约束、不重复展开，因此环不会无限递归；
   若环上带来矛盾约束，按 `incompatible` 报出。
7. **预发布**：默认排除 `a/b/rc/dev`；`allow_prereleases=true` 放开；
   或约束显式钉住预发布（如 `==2.0rc1`）时也会被接受。
8. **确定性**：候选按 PEP 440 降序、输出按键排序，重复解析同一快照与环境结果逐字节一致。
9. **升级（`/upgrade`）**：在 `/resolve` 语义上附加 `current_lock` 与 `target`。
   目标包只尝试严格高于当前版本的候选（高版本优先），取第一个能完成整体
   解析的版本；随后在该版本的所有有效解中枚举并保留“非目标包相对
   `current_lock` 变化数量最少”的解（分支定界剪枝，变化数相同按既定
   确定性顺序取先遇到者）。`/resolve` 的行为不受任何影响。
10. **审计（`/audit-lock`）**：不求解，只按 `current_lock` 的锁定版本从根包
    遍历已激活依赖：环中包只展开一次但累计全部入边约束；输出
    missing / unavailable / constraint_mismatch / extraneous 四类确定性
    排序的问题，包名按 PEP 503、版本与约束按 PEP 440 判断。
11. **依赖路径（`/dependency-paths`）**：先复用第 10 条的审计，锁无效即
    返回 409 且不查询；锁有效时按锁定版本展开已激活依赖建图，BFS 返回根包
    到目标包的全部最短包路径：菱形等长路径全保留，环不重复节点、不会无限
    遍历，路径按字典序确定性排序；目标为根包返回单节点路径，不可达返回
    `reachable: false` 与空路径。
12. **跨环境矩阵（`/resolve-matrix`）**：对同一份快照与根约束，在 2～8 个
    带唯一 `id` 的目标环境上各跑一遍第 2～8 条的同一套求解（环境间完全
    独立、各自回溯与冲突收集）。全部成功时 `results` 按 `id` 排序给出各
    环境锁定清单，`matrix` 按包名排序逐包记录各环境版本（未出现为
    `null`）：所有环境都存在且版本一致为 `shared`，否则（版本不同或仅部分
    环境出现）为 `divergent`；任一环境无解则整体 409，`failures` 按 `id`
    排序给出各失败环境与 `/resolve` 同形的原冲突结果。
13. **物料清单（`/sbom`）**：先复用第 10 条的审计，锁无效即返回 409 且不
    导出；锁有效时沿第 11 条的已激活依赖图（按锁定版本、无版本选择）逐包
    导出规范化名称、版本、PURL（`pkg:pypi/<name>@<version>`）、已激活
    依赖名称（去重排序）与候选版本携带的 `source_url` / `sha256` /
    `license` 元数据；元数据缺失不阻断导出，只在 `warnings` 中按包名逐项
    提示；`packages` 按包名排序，输出只取决于快照、环境与锁。

### 安全护栏

- **尝试上限**（默认 100,000 次候选展开）：防止恶意构造的快照造成指数级搜索，
  超出返回 `409 / status:"limit"`。
- **依赖链深度上限**（默认 5,000 层）：超出同样以 `limit` 报出，而不是进程栈溢出。

## 四、项目结构

```
app/
  main.py        # FastAPI 路由与错误映射
  resolver.py    # 回溯求解器（候选排序 / MRV / 来源链重建）
  audit.py       # 锁定清单审计（按锁版本遍历 / 环中累计入边 / 四类问题）
  paths.py       # 锁定依赖图建图与根包到目标包的全部最短路径（菱形/环安全）
  sbom.py        # 沿已激活依赖图导出确定性 JSON SBOM（PURL / 元数据 / 缺失 warnings）
  repository.py  # 快照规范化、PEP 440/503 解析、按环境过滤 marker、候选元数据校验
  markers.py     # PEP 508 marker 解析/白名单校验/环境求值（不读宿主机）
  schemas.py     # 请求/响应模型
examples/        # curl 示例请求体（含跨环境 marker、/resolve-matrix、/upgrade、/audit-lock、/dependency-paths、/sbom 示例）
tests/           # 求解器与 HTTP 层测试（pytest + FastAPI TestClient）
Dockerfile
docker-compose.yml
requirements.txt
```

## 五、运行测试

```bash
.venv/bin/pip install pytest httpx
.venv/bin/python -m pytest -q
```
