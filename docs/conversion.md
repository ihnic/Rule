# 转换规则与引用方式

本项目把 `custom/*.txt` 和远程规则源转换为各端可使用的规则文件。转换保留匹配含义；目标格式无法表达的类型，不会通过改写成域名来替代。

当前支持下表中的规则类型和简写。geosite 展开后如遇到尚不能在各端无损转换的类型（例如 `DOMAIN-REGEX`），构建会明确报错并保留原产物，避免只导出其中一部分规则。

无法保留语义的参数（例如 `src`、`extended-matching`）也会明确报错。IP / ASN 支持 `no-resolve`；输入中可选的内置策略值会被移除，最终策略由客户端引用该规则集时指定。

| 输入规则 | Surge RULE-SET | Mihomo 输出 | MosDNS v5 domain_set |
| --- | --- | --- | --- |
| `DOMAIN,example.com` / `full:example.com` | `DOMAIN,example.com` | domain：`example.com` | `full:example.com` |
| `DOMAIN-SUFFIX,example.com` / `domain:example.com` | `DOMAIN-SUFFIX,example.com` | domain：`+.example.com` | `domain:example.com` |
| `DOMAIN-KEYWORD,example` / `keyword:example` | `DOMAIN-KEYWORD,example` | classical：`DOMAIN-KEYWORD,example` | `keyword:example`；尾点情况见下文 |
| `IP-CIDR,192.0.2.0/24,no-resolve` | 保留 IPv4 类型和参数 | ipcidr：`192.0.2.0/24`；解析行为见下文 | 无法在域名集合中表达 |
| `IP-CIDR6,2001:db8::/32,no-resolve` | `IP-CIDR6,2001:db8::/32,no-resolve` | ipcidr：`2001:db8::/32`；解析行为见下文 | 无法在域名集合中表达 |
| `IP-ASN,399358,no-resolve` | 保留 ASN 和参数 | classical：`IP-ASN,399358,no-resolve` | 无法在域名集合中表达 |
| `PROCESS-NAME,example` | `PROCESS-NAME,example` | classical：`PROCESS-NAME,example` | 无法在域名集合中表达 |
| `geosite:标签` | 构建时展开，再按各条规则转换 | 构建时展开，再分入对应类型 | 构建时展开，再输出域名规则 |
| `geosite:集合@属性` / `geosite:集合@!属性` | 展开属性分类 / 未标该属性的条目后转换 | 同左，再分入对应类型 | 同左，再输出域名规则 |

**关键词与后缀。** `keyword:sentry` 和 `DOMAIN-KEYWORD,sentry` 表示域名包含 `sentry` 这一子串。`DOMAIN-SUFFIX,sentry.io` 只匹配 `sentry.io` 及其子域，不等价于前者。例如 `sentry.example.com` 命中关键词，但不命中 `sentry.io` 后缀。关键词不解释为正则或通配符，也不能包含空白。

MosDNS 的原生关键词匹配会转小写并去掉关键词尾点，因此直接输出 `keyword:test.` 会扩大成 `test` 子串。为保留原意，转换器把以点结尾的关键词输出为转义后的字面量正则，例如 `regexp:(?i)test\.`；它匹配 `test.example.com`，不匹配 `testdrive.example.com`。普通关键词仍输出 `keyword:`。这属于转换器生成的等价表达，不表示支持任意正则输入。

**geosite 的数据来源。** `geosite:anthropic` 在构建时读取 MetaCubeX 的[已展开 anthropic classical 列表](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/anthropic.list)，`geosite:category-ntp` 对应[已展开 NTP classical 列表](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ntp.list)。采用 `geo/geosite/classical/` 下的导出，以保留原始规则类型；普通 domain 导出可能不包含关键词或正则规则。输出文件包含实际规则，不保留 `geosite:` 引用；跟随上游更新需要重新构建。

这与让客户端读取自己配置的 `geosite.dat` 有区别：相同标签在不同数据来源、版本或属性筛选下可能包含不同域名。本项目以构建时获取的 MetaCubeX 列表为准。不要把 v2fly 原始源文件里的 `include:` 当作普通域名；例如 `category-ntp` 还包含 `category-ntp-cn` 和 `category-ntp-jp`，应使用已经展开这些引用的导出列表。

<a name="ntp-split"></a>

**NTP 按 cn 分类分流。** 时间服务独立于 Anthropic 集合，使用下列来源文件。条数以 2026-11-17 获取的上游内容为准，后续跟随上游更新。

| 输出集合 | custom 内容 | 当前条数 | 含义 |
| --- | --- | ---: | --- |
| `category-ntp-cn` | `geosite:category-ntp@cn` | 23 | 上游标记 `cn` 的时间服务 |
| `category-ntp-!cn` | `geosite:category-ntp@!cn` | 93 | NTP 全集里未标记 `cn` 的条目 |
| `category-ntp` | `geosite:category-ntp` | 116 | 保留全集，兼容原有订阅 |

国内分类读取 MetaCubeX 的 [`category-ntp@cn` 导出](https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/category-ntp%40cn.list)。上游没有 `category-ntp@!cn` 导出文件；转换器读取全集和正向属性分类，按规范化后的规则条目计算差集，生成未标记 `cn` 的集合。`cn` 是上游分类属性，不能保证域名每次解析出的服务器 IP 都在中国大陆；`!cn` 也不等于已验证的境外服务器清单。

**使用时先匹配 `category-ntp-cn`，再匹配 `category-ntp-!cn`。** 未标 `cn` 的集合保留了 `DOMAIN-SUFFIX,pool.ntp.org`，其匹配范围包括国内集合里的 `cn.pool.ntp.org` 及其子域。两个文件没有相同规则条目，但域名后缀仍有覆盖关系；把国内组放在前面，才能让这些国内子域采用国内策略。启用拆分后，使用下面两组引用；原全集仍可供采用统一策略的配置订阅。

Surge 将以下两行加入 `[Rule]`，并放在可能提前命中的通用规则和最终兜底规则之前。`NTP-其他` 请替换为已有策略组；这里示例让国内分类走 `DIRECT`。

```ini
RULE-SET,https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-ntp-cn.list,DIRECT
RULE-SET,https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-ntp-%21cn.list,NTP-其他
```

Mihomo 合并以下提供者和规则，保持相同的先后顺序，并将 `NTP-其他` 替换为已有策略组。Raw URL 中的 `%21` 表示文件名中的 `!`。

```yaml
rule-providers:
  ntp-cn:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-ntp-cn_domain.mrs
    path: ./ruleset/ntp-cn.mrs
    interval: 900
  ntp-not-cn:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-ntp-%21cn_domain.mrs
    path: ./ruleset/ntp-not-cn.mrs
    interval: 900

rules:
  - RULE-SET,ntp-cn,DIRECT
  - RULE-SET,ntp-not-cn,NTP-其他
```

MosDNS 分别下载 [cn 域名文件](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-ntp-cn.txt)和[未标 cn 的域名文件](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-ntp-%21cn.txt)，通过两个 `domain_set` 加载。`domain_set` 本身没有路由优先级，需要在调用它们的 `sequence` 中先处理国内集合：国内分支完成解析后用 `accept` 结束处理；若后续仍会进入其他分支，`!cn` 分支必须同时要求“不命中国内集合”。仅按顺序声明两个 `domain_set`，不能阻止 `pool.ntp.org` 后缀再次匹配国内子域。

**Surge。** 使用 `surge/*.list` 作为 RULE-SET。IPv4 必须使用 `IP-CIDR`，IPv6 使用 `IP-CIDR6`；规则集可包含 `IP-ASN`，也可保留各行的 `no-resolve`。`no-resolve` 表示该规则不主动为尚未解析的域名发起 DNS 查询，已有目标 IP 仍可参与匹配。

**MosDNS。** `mosdns/*.txt` 是 `domain_set` 的域名匹配文件，承载精确域名、后缀和关键词，以及上述保留关键词字面含义的正则。它不承载目标 IP 段、ASN、进程名或连接路由；因此不能把 MosDNS 文件与 Surge 完整规则集当作包含相同类型的规则。IP / ASN 的 `no-resolve` 也没有可写入此域名集合的对应参数。

**Mihomo。** 本项目按能力拆分输出，存在的分类需要一起引用：

- `mihomo/domain/*_domain.mrs`：精确域名和后缀，使用 `behavior: domain`、`format: mrs`。
- `mihomo/ip/*_ip.mrs`：IPv4 / IPv6 网段，使用 `behavior: ipcidr`、`format: mrs`。
- `mihomo/classical/*.list`：关键词、ASN、进程等补充规则，使用 `behavior: classical`、`format: text`。它不是该集合的完整全集，不能只引用这一份。

MRS 目前仅支持 `domain` 和 `ipcidr` 行为。IP MRS 只保存网段，不保存每条规则的 `no-resolve`；需要在引用处写成 `RULE-SET,集合名,策略,no-resolve`。该参数作用于整个集合，所以同一 IP MRS 不能分别保留部分网段主动解析、部分网段不解析的差异；需要这种差异时，应拆成两个集合分别引用。Anthropic 的两个 IP 段都带 `no-resolve`，可以使用同一个 IP MRS。

classical 文本则能保留 ASN 行上的参数，例如：

```text
DOMAIN-KEYWORD,datadog
DOMAIN-KEYWORD,sentry
DOMAIN-KEYWORD,sift
IP-ASN,399358,no-resolve
```

下面的片段使用仓库发布的 Anthropic 三类文件。把它合并到已有 Mihomo 配置，并把 `Anthropic` 换成现有策略组名；这些规则应放在需要它们优先匹配的其他规则和最终兜底规则之前。

```yaml
rule-providers:
  anthropic-domain:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/anthropic_domain.mrs
    path: ./ruleset/anthropic_domain.mrs
    interval: 900
  anthropic-ip:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/anthropic_ip.mrs
    path: ./ruleset/anthropic_ip.mrs
    interval: 900
  anthropic-classical:
    type: http
    behavior: classical
    format: text
    url: https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/anthropic.list
    path: ./ruleset/anthropic_classical.list
    interval: 900

rules:
  - RULE-SET,anthropic-domain,Anthropic
  - RULE-SET,anthropic-classical,Anthropic
  - RULE-SET,anthropic-ip,Anthropic,no-resolve
```

ASN 规则需使用客户端的 ASN 数据库，实际匹配也取决于该数据库的内容和版本。上述 classical 引用不需要再统一添加 `no-resolve`，因为示例中的 ASN 行已保留该参数。

**本地运行。** 在仓库根目录执行；Python 需安装 `requests`，Mihomo 内核需与运行系统匹配。默认使用仓库中的 `./mihomo-core`，可通过 `MIHOMO_BIN` 指定其他可执行文件。

```sh
# 检查所有源并更新有变化的规则集
python3 main.py

# 只更新指定规则集，其他组的产物和缓存记录不变
python3 main.py --only category-ntp-cn 'category-ntp-!cn'

# 指定本机可执行的内核
MIHOMO_BIN=/absolute/path/to/mihomo python3 main.py --only anthropic

# 强制重建所选组，仍需通过下载、解析和编译检查
FORCE_UPDATE=true python3 main.py --only category-ntp-cn 'category-ntp-!cn'
```

**GitHub Actions 触发与缓存。** 工作流位于 [update_rules.yml](../.github/workflows/update_rules.yml)，使用 Python 3.10，并在转换前执行语义测试。

| 触发方式 | 更新行为 |
| --- | --- |
| 推送规则相关改动 | `custom/**`、`rules.txt`、`main.py`、`readme.py`、`mihomo-core`、`tests/**` 或工作流文件发生变化时立即触发排队，处理当前分支 |
| 定时检查上游 | UTC 每小时的 07、22、37、52 分，在默认分支检查远程规则和 geosite 更新 |
| Actions 页面手动运行 | 可选 `force_update` 强制重建，用于需要立即检查或修复产物的情况 |

另有独立的[规则清理并全量重建](../.github/workflows/rebuild_rules.yml)工作流，仅支持手动触发。在 GitHub 仓库的 **Actions → 规则清理并全量重建 → Run workflow** 中选择分支运行。

它从空临时目录重新获取和转换所有当前来源，不读取旧 `versions.json` 或任何旧产物。全部来源成功后，整体替换 `mihomo/`、`surge/`、`mosdns/`、`versions.json` 和 README，再提交推送；因此也会清掉没有记入版本缓存的历史孤儿文件。`custom/`、`rules.txt`、转换脚本和内核作为输入保留。

与普通工作流的 `force_update` 不同，这个入口会完整替换生成目录；任一来源下载、解析或编译失败时，整次重建停止，不发布部分结果。零规则组也会停止替换。它与自动更新共享同一分支的并发锁，并在推送前检查远端是否出现新提交。

这不是严格实时同步。GitHub 官方允许的最短定时间隔为 5 分钟；高负载时任务可能延迟，甚至被丢弃。错开整点可以降低排队概率，但不保证固定完成时间。定时工作流只在默认分支运行；公共仓库连续 60 天没有仓库活动时，GitHub 会自动禁用定时运行，需要在 Actions 中重新启用。本工作流不监听 PR 或 fork 事件；fork 仓库启用 Actions 后，可以运行其自身的分支更新任务。

`versions.json` 是随生成文件一起提交的版本记录，不是阻止下载的 HTTP 缓存。每次运行都会重新获取选中组的远程源和 geosite 依赖，geosite 仅在同一次运行中复用下载结果。缓存签名包含展开并合并后的规则内容、`main.py` 代码哈希，以及实际 `MIHOMO_BIN` 文件的 SHA-256；规则、转换器或编译内核变化都会触发重建。预期文件缺失、存在过期分类产物，或启用强制更新时，也会重新生成。失败组保留旧版本记录，下一次仍会重试。README 由 `readme.py` 在每次运行时重新生成，修改索引生成逻辑不需要让全部 MRS 缓存失效。

完整运行还会清理已从来源配置中移除的规则组及其版本记录，避免删除 custom 文件或远程订阅后仍保留旧规则；只清理由版本记录管理的组。`--only` 定向运行不清理其他组。

工作流按 `rules-update-分支引用` 并发组串行执行同一分支的任务，不同分支可独立运行；新的触发不会中断该分支正在运行的任务。GitHub 默认只保留一个待运行任务，后来的触发可能替换先前排队的任务。开始执行时检出当前运行分支的最新内容；推送前再次获取远端头，若运行期间分支已变化，就明确失败并要求重跑，不把旧输入生成的结果移到新提交上。检查后若再发生竞争，普通推送仍会拒绝非快进更新，不使用强制推送。

只提交 `README.md`、`versions.json`、`mihomo/`、`surge/`、`mosdns/`，没有变化时不创建提交。部分规则组失败时，工作流仍尝试提交已经成功更新的组，最后在日志和运行摘要中明确报告失败，并保持整次运行失败；测试失败时不会进入转换和发布。

仓库成功发布后，客户端还要拉取更新。上面的 Mihomo 示例使用 `interval: 900`，即每 15 分钟检查；Surge 可在 RULE-SET 引用处设置 `update-interval=900`。MosDNS 使用本地文件时，部署端还需下载新文件并重新加载规则。仓库的检查频率不会自动覆盖客户端刷新频率，也不能消除下载缓存或网络延迟。

**核对依据（2026-11-17）。**

- Surge 官方：[域名规则](https://manual.nssurge.com/rules/domain.html)、[IP / IPv6 / ASN 规则](https://manual.nssurge.com/rules/ip.html)、[RULE-SET 格式与参数](https://manual.nssurge.com/rules/ruleset.html)。
- Mihomo 官方：[规则提供者与 MRS 支持范围](https://wiki.metacubex.one/config/rule-providers/)、[IP-ASN 参数解析](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/parser.go)、[ASN 的 no-resolve 行为](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/common/ipasn.go)、[ipcidr 集合实现](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/provider/ipcidr_strategy.go)、[RULE-SET 的 no-resolve 行为](https://github.com/MetaCubeX/mihomo/blob/Meta/rules/provider/rule_set.go)。
- MosDNS v5 官方实现：[支持的域名类型与关键词匹配](https://github.com/IrineSistiana/mosdns/blob/v5/pkg/matcher/domain/matcher.go)、[大小写与尾点处理](https://github.com/IrineSistiana/mosdns/blob/v5/pkg/matcher/domain/utils.go)、[domain_set 文件加载](https://github.com/IrineSistiana/mosdns/blob/v5/plugin/data_provider/domain_set/domain_set.go)。
- geosite 上游：[v2fly 源格式与 include 语义](https://github.com/v2fly/domain-list-community#syntax)、[category-ntp 原始源](https://github.com/v2fly/domain-list-community/blob/master/data/category-ntp)、[MetaCubeX classical 导出](https://github.com/MetaCubeX/meta-rules-dat/tree/meta/geo/geosite/classical)。
- GitHub 官方：[定时触发、延迟、默认分支与 60 天限制](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)、[并发组与待运行任务](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)。
