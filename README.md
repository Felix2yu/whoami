# whoami

一个零依赖的 Go 单进程服务：访客打开页面（或别的页面用 iframe 嵌它）就能看到自己的
IP、操作系统、CPU 架构、浏览器、GPU 等信息，并尽可能判断这台机器**是不是信创终端 / 国产系统**。

定位是**自助排查与终端盘点**，不是准入依据。页面默认只有一张结果表（是否信创、IP 与所处网络、
系统、架构、浏览器、GPU 各占一行），判定依据、置信度和原始证据都收在 `?detail=1` 里，
完整结论任何时候都能从 `/api/whoami` 拿到。「是否信创」给四态短答：**是 / 疑似 / 不是 / 未知**——
只有拿到确证信号才说「不是」（macOS、Windows 这类境外系统本身就不在信创目录内），
判不出来的（国产 x86 与 Intel/AMD 无法区分）一律「未知」，不会硬给否定结论。

## 快速开始

```bash
go build -o bin/whoami ./cmd/whoami
./bin/whoami -addr 127.0.0.1:8080
```

打开 <http://127.0.0.1:8080/> 即可。页面先按请求头出一版结论，
浏览器端的 JavaScript 跑起来后会把 Client Hints、WebGL GPU 等回报给服务端，
服务端重新判定并返回渲染好的片段替换整块结果，判定逻辑始终只有服务端一套。

## 参数

| flag | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `-addr` | `WHOAMI_ADDR` | `127.0.0.1:8080` | 监听地址 |
| `-trusted-proxies` | `WHOAMI_TRUSTED_PROXIES` | 空 | 受信反代 CIDR，逗号分隔。**留空表示不信任任何代理头**，XFF 一律不采用 |
| `-ip-dict` | `WHOAMI_IP_DICT` | 空 | IP 归属字典路径，见下 |
| `-frame-ancestors` | `WHOAMI_FRAME_ANCESTORS` | 空 | 允许 iframe 嵌入的来源白名单；留空输出 `frame-ancestors *` |
| `-log-dir` | `WHOAMI_LOG_DIR` | `data/logs` | 访问日志目录，留空即关闭落盘 |
| `-log-keep-days` | `WHOAMI_LOG_KEEP_DAYS` | `90` | 启动时清理超过该天数的日志（只认自己写出的 `whoami-YYYYMMDD.jsonl`） |
| `-stats-replay-days` | `WHOAMI_STATS_REPLAY_DAYS` | `7` | 启动时回放多少天日志重建统计（单次扫描上限 20MB） |
| `-anonymize-ip` | `WHOAMI_ANONYMIZE_IP` | `off` | 日志/统计里的地址脱敏：`off` / `last-octet`（v4 归 /24、v6 归 /64）/ `full`（加盐哈希，仍可去重） |
| `-rules` | `WHOAMI_RULES` | 空 | 外部规则 JSON，同 ID 覆盖内置规则 |
| `-ip-geo-endpoint` | `WHOAMI_IP_GEO_ENDPOINT` | 空 | IP 归属查询接口，`{ip}` 会被替换。**默认不外呼**，启用即意味着把访客 IP 交给第三方 |
| `-ip-geo-fields` | `WHOAMI_IP_GEO_FIELDS` | `country,province,city,isp,asn` | 从归属接口响应里取哪些键 |

超时与体积的默认值按真实量级定：`ReadHeaderTimeout 5s / Read 10s / Write 15s / Idle 60s`，
`MaxHeaderBytes 64KiB`，浏览器端回报 `32KiB`（实际 payload 2–4KB），单条证据展示截断 512B，
JSON 输出上限 1MiB。

## 容器

```bash
./build.sh                      # 产出 bin/whoami（装配式镜像的二进制来源）
docker build -t whoami .        # 本机没有 docker 时这一步交给 CI
docker run --rm -p 8080:8080 -v whoami-data:/data whoami
```

镜像是装配式的：`alpine:3.24` + 非 root 用户 + `COPY bin/whoami`，没有 Go/Node 构建阶段，
因为页面资源已经通过 `go:embed` 进了二进制。

容器里有两个和裸机不同的默认值，都是刻意的：

- `WHOAMI_ADDR=:8080`：进程内默认监听 `127.0.0.1:8080`（本机跑不暴露到局域网），
  容器里必须放开到所有网卡。用环境变量而不是写死 `ENTRYPOINT` 参数，
  是因为 `cmd/whoami` 的 flag 默认值读 env，你显式传 `-addr` 仍然优先。
- `WHOAMI_LOG_DIR=/data/logs` + `VOLUME`：日志和 IP 字典都挂 `/data` 就能跨重启保留，
  统计会在启动时回放这些日志重建。

监听地址、日志目录等全部走同一套 flag/env（见下表），compose 里改 env 即可，不用覆盖命令。

本地实测：`CGO_ENABLED=0 GOOS=linux go build` 产物 `file` 判定为 `ELF ... statically linked`、
无 `PT_INTERP`，所以 CI 的 `cgo: off` 分支是真静态，装进 musl 不会 ENOENT。
`build.sh` 里带同一条校验（本机没 `readelf` 时跳过并说明）。

## 端点

| 路径 | 说明 |
| --- | --- |
| `GET /` | 检测页 |
| `GET /api/whoami` | 纯服务端信号的 JSON 结论 |
| `POST /api/whoami` | 接收浏览器端回报，返回合并后的 JSON 结论 |
| `POST /report` | 接收同一份回报，返回渲染好的 HTML 片段（页面的 JS 用它） |
| `GET /stats`、`GET /api/stats` | 访问统计页 / JSON |
| `GET /api/rules` | 导出当前真正生效的规则表（内置 + 外部覆盖后） |
| `GET /healthz` | 存活探测 |

## 嵌到别的页面里

```html
<iframe src="http://whoami.internal:8080/" width="100%" height="520"
        title="访客设备信息" loading="lazy"></iframe>
```

- **自动紧凑版式**：请求带 `Sec-Fetch-Dest: iframe` 时页面自己切紧凑布局，宿主页面不用加参数。
  想手动控制就用 `?embed=1` / `?embed=0`。
- **详略开关**：默认只有结果表，`?detail=1` 才展开每行的来源、判定分、边界说明与原始证据
  （页脚那句免责也跟着它）。`?detail=0` 显式关掉，写了参数不等于开启。
- **卡片开关**：`?hide=ip,cpu,evidence` 关掉某些行，`?only=cpu,browser` 只留某些行。
  可用键见 `internal/whoami/framing.go` 的 `allCardKeys()`，其中 `verdict` 就是「是否信创」那一行。
  如果你暂时保留旧的 IP 检测 iframe，加 `?hide=ip` 就行。
- **不设 `X-Frame-Options`，也不设 COEP/CORP**：后者会让跨源 iframe 直接白屏。
  要限制谁能嵌，配 `-frame-ancestors 'http://host:port'`。
- **JS 回报是同源请求**：iframe 里的文档由 whoami 自己出，`POST /report` 打回自己这个源，
  所以不需要 CORS 配置。
- **自适应高度**：页面会向宿主 `postMessage({type:'whoami:height', height})`，
  宿主按 `e.source` 匹配到对应 iframe 后把 `style.height` 设成该值即可（见 `examples/embed-host.html`）。
- 宿主页面如果给 iframe 加了 `sandbox` 但没给 `allow-scripts`，JS 不会执行；
  `?detail=1` 会显式写「仅服务端信号，未做跨源交叉验证」，不会假装什么都没发生。
- 收紧过 `allow` 属性的话需要放行 Client Hints：
  `allow="ch-ua-arch; ch-ua-model; ch-ua-platform; ch-ua-platform-version; ch-ua-full-version-list"`。
- 非 https（内网直连 IP 很常见）时浏览器可能不给高熵值，页面对应字段整行不渲染，
  并在 `?detail=1` 的证据区说明 `js.hintsUnavailable`。
  受这个限制的是 `设备内存`、`系统版本`、CH 的 `architecture`/`model`；
  **不受影响的**有 WebGL 显卡串、逻辑核心数、屏幕、时区、语言——所以 http 下也照样能判「不是」。
- `navigator.platform` 也不受安全上下文限制，被采作**系统家族的兜底来源**（`MacIntel`→macOS、
  `Win32`→windows、`Linux x86_64`→linux、`iPhone`→ios）。采信条件是「没人说过系统家族」
  或「说的正是它」：安卓 Chrome 报 Linux、iPadOS 桌面模式报 MacIntel，矛盾时一律让位给 UA，
  但原值仍留在 `js.navigatorPlatform` 证据里。这个字段已被 W3C 标为弃用，只当旁证用。
- 不使用任何浏览器存储，所以第三方 iframe 的存储分区策略对它没有影响。

跨源 iframe 的实测可以在本地起一个宿主页：

```bash
python3 -m http.server 9099 -d examples   # 另一个端口，制造跨源场景
# 然后打开 http://127.0.0.1:9099/embed-host.html
```

## IP 归属字典

```
# ip.csv：CIDR 或裸 IP，逗号，标签
10.0.0.0/8,总部内网
10.1.0.0/16,三分局出口
2.46.0.0/24,某运营商会馆出口
114.242.1.1,张三的笔记本
```

- 最长前缀匹配：`10.1.2.3` 命中 `10.1.0.0/16` 而不是 `/8`。
- 裸 IP 自动补 `/32`（v6 补 `/128`），IPv4-mapped IPv6 会先还原再查。
- `#` 起注释；格式错的行被跳过，条目数与跳过原因都能在 `/api/stats` 附近和启动日志看到，不会静默吞掉。
- 文件改完约 10 秒内自动重载，不用重启进程。
- 内置识别 RFC1918、CGNAT `100.64/10`、loopback、link-local、ULA，命中即标注「内网/保留地址」。

参考模板见 `ip.example.csv`。

## 信创识别是怎么做的

规则表是**数据**，不是 if-else。一条规则长这样（`internal/whoami/rules.go`）：

```go
r("cpu-loongarch64", FieldArch, e("loongarch64", "loongarch"), "龙芯 LoongArch",
  "CPU 架构", CatCPU, 100, 100, "LoongArch 自研指令集只在龙芯上出现").xc()
```

打分链路：

1. **抽信号**：连接层、请求头、`Sec-CH-UA*`、浏览器回报，统一归一到 `arch` / `platform` /
   `ua` / `brand` / `gpu` 等字段。Client Hints 的 `arm`+`64` 会被还原成 `aarch64`，
   与 UA 的词表对齐，否则会被当成两个不同结论。
2. **匹配**：`Match` 支持 `Contains / Word / Prefix / Equals / Regex / Not` 与 `CaseFold`，
   同一子句内是「或」，不同子句之间是「与」，`CaseFold` 沿整条规则继承。
3. **合并**：同一类别同一结论的多条规则并成一个 Finding，来源集合去重。
4. **抑制**：`Suppresses` 声明互斥，例如安卓上报的 ARM 会被压掉信创含义。
5. **冲突**：同一类别出现两个不同的**信创**结论（比如 UA 里同时有 UOS 与 Kylin），
   两条都降到 60 分以内，也就是「疑似」，两条都保留展示。
6. **跨源一致**：`header` 与 `js` 说出同一件事，证据强度 +40。
7. **天花板**：`Ceiling` 是「这类信号单独最多能说明到什么程度」。
   跨源一致**突破不了它**——两个来源都同意「这是 aarch64」，也只能证明架构，
   不能证明它是飞腾还是树莓派。
8. **境外平台**：`Foreign` 标记「确证在信创目录之外」的信号。没有任何信创信号、
   且境外证据 ≥80 时给 `excluded`（页面显示「不是」）；有信创信号时仍以信创信号为准
   （奇安信浏览器也有 Windows 版，谁更硬交给打分，不由系统家族一票否决）。
   目前只有两类信号够格：**系统家族**（macOS/Windows/iOS/ChromeOS/BSD）和
   **Apple 显卡**（WebGL 串里的 `Apple` 只能来自 Apple 整机）。
   安卓与鸿蒙**不给**否定结论：国产平板和鸿蒙兼容层同样报 Android；
   Intel/NVIDIA/AMD 显卡也不给：国产整机照样插境外独显。

置信度阈值：`≥80 确认`、`≥40 疑似`、其余 `未知`；`excluded` 走上面第 8 条，不参与打分。

### 行序

结果表按 `view.go` 的 `rowOrder` 排：结论 → IP 与归属 → 系统家族/发行版/系统版本 →
CPU 架构/核心数/内存 → GPU 结论/原始串 → 浏览器/内核/Client Hints → 机型/屏幕/时区。
加新字段时在表里给个位次，否则它会落到最后而不是插进不相干的分组中间。

已确认真实存在的 token 只有少数几个：统信 UA 里的 `UOS`、麒麟的 `Kylinbrowser`、
奇安信的 `Qaxbrowser`，加上架构串 `loongarch64` / `sw_64` / `mips64`。
`openEuler` / `Anolis` / 方德 / 普华 / 红莲花这些条目标了 `verified:false`，
是**预留坑位**，等你用真机 F12 看到实际 token 后补进规则表。

### 追加 token 不用改代码

```bash
curl -s localhost:8080/api/rules | jq '.rules' > rules.json   # 先拿现成的结构
# 编辑：新增一条，或改已有条目的 ceiling/token
./bin/whoami -rules rules.json
```

同 ID 直接覆盖内置规则，改完 `/api/rules` 里能看到 `external`/`replaced` 计数。

## 检测不到的情况

真实边界，页面与 `/api/whoami` 都会如实说出来：

| 情况 | 后果 |
| --- | --- |
| 企业策略把 UA 冻结成通用 Chrome 串 | Linux 上判不出来，只能给「未知」；串里带 Windows/macOS 的仍能定系统家族，给「不是」 |
| 海光、兆芯的国产 x86 | **任何 HTTP 信号都无法与 Intel/AMD 区分**，这是方法本身的天花板 |
| Safari 的精简 UA | 平台细节缺失，Apple 芯片连架构都不给（macOS 家族本身已足够判「不是」） |
| 浏览器禁用 JS、iframe `sandbox` 缺 `allow-scripts` | 只有请求头信号 |
| 非安全上下文（内网 http） | Client Hints 高熵值可能拿不到 |
| WebGL 被禁用或屏蔽 unmasked 参数 | 没有 GPU 旁证；软件渲染（SwiftShader/llvmpipe）与虚拟显卡不算反证。例外是 `Apple` 串，它能单独给「不是」 |
| WSL2、容器 | 上报 Linux，宿主信息缺失 |
| DevTools / 代理伪造 | 所有信号都可伪造，包括 WebGL 厂商串 |

`aarch64` 只能到「疑似」不是实现偷懒：飞腾/鲲鹏是信创主力，但同一时刻树莓派、
安卓机与 Apple 芯片也都报 aarch64。

## 日志与统计

- 追加式 JSONL，按天一个文件 `data/logs/whoami-YYYYMMDD.jsonl`，一行一次请求，
  带 `kind`（`page` / `report` / `api`）。低流量场景每条同步落盘，进程被杀不丢已写的记录。
- **统计口径**：`页面访问` 只数 `kind=page`；一次访客打开页面会产生 1 条 page +
  （JS 正常时）1 条 report，混在一起会让总访问量翻倍，所以两套分布分开统计：
  「请求头判定的分布」与「合并浏览器端回报后的分布」。
- 维度：状态三态、发行版、CPU 架构、浏览器、IP 归属标签、iframe 宿主、近 30 天序列、
  JS 回报覆盖率。每组按计数降序取前 10，其余并入「其它」。
- 日志是唯一真源：启动时回放最近 N 天日志重建计数，不引入数据库。重启后 `/stats` 的数字不变。
- 访客 IP 是个人信息。默认落盘保留完整地址（便于你自己排查），要对外提供服务就开
  `-anonymize-ip last-octet` 或 `full`；`full` 的盐持久化在日志目录 `.anon-salt`（0600），
  看不出原地址，且重启后 `独立 IP` 计数仍然正确。
- 默认不外呼任何第三方归属接口。要接你现有的 IP 服务，实现
  `internal/whoami/ipgeo.go` 里的 `IpInfoProvider` 接口即可。

## CI

`.github/workflows/ci.yml` 转调组织统一的复用流水线（`Felix2yu/.github` 的 `@v1`）：

- `test` → `reusable-test.yml`，`test-flags: -race -covermode=atomic`（判定链、日志与统计都要求并发安全）
- `image` → `reusable-image.yml`，`cgo: off`、`main-package: ./cmd/whoami`，推 `ghcr.io/felix2yu/whoami`
- `release` → `reusable-release.yml`，仅在 `release: published` 时跑多平台产物

没有 `web-dir` / `frontend-stage-command`：仓库里没有需要 Node 构建的前端，
JS/CSS 是直接 `go:embed` 的源文件。工具链版本由 `go.mod` 声明，workflow 里不写死。

## 测试

```bash
go vet ./...
go test ./... -race
go test ./internal/whoami -fuzz=FuzzMatcher -fuzztime=30s
go test ./internal/whoami -fuzz=FuzzBrowserReport -fuzztime=30s
```

识别相关的关键语料在 `internal/whoami/testdata/`：`ua_cases.tsv` 断言命中哪些规则，
`verdict_cases.tsv` 断言最终三态结论。加一条真机 UA 就往文件里加一行，
不用改测试代码。
