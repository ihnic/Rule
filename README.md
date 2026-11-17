# Rule · 规则集

适用于 Surge、Mihomo 与 MosDNS。每行对应一组规则，索引中的订阅链接均为 `main` 分支的 Raw 地址。

[规则索引](#规则索引) · [复制地址](#复制地址) · [转换语义与配置示例](docs/conversion.md)

来源或转换逻辑提交后自动更新；上游每 15 分钟检查一次，实际运行时间以 GitHub Actions 调度为准。

需要清掉历史规则和旧缓存时，可在 Actions 中手动运行[规则清理并全量重建](https://github.com/ihnic/Rule/actions/workflows/rebuild_rules.yml)。全部来源重建成功后，才整体替换旧产物。

- **Surge**：使用 `RULE-SET`；**MosDNS**：使用 `domain_set`，仅包含域名与关键词。
- **Mihomo**：域名与 IP 优先提供 MRS；补充文件使用 `classical / text`，包含关键词、ASN、进程等规则，**不是完整全集**。请一起引用需要的分类。
- **IP 解析**：Mihomo IP MRS 不保存逐条 `no-resolve`；需要禁止主动解析时，在引用处添加 `RULE-SET,集合名,策略,no-resolve`。

## 规则索引

共 **34** 组规则。点击格式查看 Raw 文件；点击规则名称前往该组的复制区。`—` 表示没有此类文件。

| 规则 | Surge | Mihomo 域名 | Mihomo IP | Mihomo 补充 | MosDNS |
| :--- | :---: | :---: | :---: | :---: | :---: |
| [anthropic](#copy-anthropic-c70eca6b) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/anthropic.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/anthropic_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/anthropic_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/anthropic.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/anthropic.txt) |
| [Apple](#copy-apple-f223faa9) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Apple.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Apple_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Apple_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Apple.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Apple.txt) |
| [apple-cn](#copy-apple-cn-4f609836) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/apple-cn.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/apple-cn_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/apple-cn.txt) |
| [BiliBili](#copy-bilibili-94a36106) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/BiliBili.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/BiliBili_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/BiliBili_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/BiliBili.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/BiliBili.txt) |
| [category-ai-chat-!cn](#copy-category-ai-chat--cn-78cbd39a) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-ai-chat-%21cn.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-ai-chat-%21cn_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-ai-chat-%21cn.txt) |
| [category-ntp](#copy-category-ntp-f769d60c) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-ntp.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-ntp_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-ntp.txt) |
| [category-speedtest-cn](#copy-category-speedtest-cn-d3c61f2c) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-speedtest-cn.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-speedtest-cn_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-speedtest-cn.txt) |
| [ChinaMax](#copy-chinamax-7cb9cda8) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/ChinaMax.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/ChinaMax_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/ChinaMax_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/ChinaMax.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/ChinaMax.txt) |
| [custom_direct](#copy-custom_direct-f01bfe9b) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/custom_direct.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/custom_direct_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/custom_direct_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/custom_direct.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/custom_direct.txt) |
| [custom_proxy](#copy-custom_proxy-1e9dc596) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/custom_proxy.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/custom_proxy_domain.mrs) | — | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/custom_proxy.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/custom_proxy.txt) |
| [Docker](#copy-docker-e6169e95) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Docker.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Docker_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Docker.txt) |
| [Epic](#copy-epic-a93d3898) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Epic.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Epic_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Epic.txt) |
| [GitHub](#copy-github-f911e414) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/GitHub.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/GitHub_domain.mrs) | — | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/GitHub.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/GitHub.txt) |
| [GlobalMedia](#copy-globalmedia-c23e9780) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/GlobalMedia.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/GlobalMedia_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/GlobalMedia_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/GlobalMedia.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/GlobalMedia.txt) |
| [Google](#copy-google-ce770667) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Google.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Google_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Google_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Google.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Google.txt) |
| [GoogleFCM](#copy-googlefcm-99edb493) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/GoogleFCM.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/GoogleFCM_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/GoogleFCM_ip.mrs) | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/GoogleFCM.txt) |
| [hk_balance](#copy-hk_balance-8bfbb23c) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/hk_balance.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/hk_balance_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/hk_balance.txt) |
| [jp_only](#copy-jp_only-9ef4a483) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/jp_only.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/jp_only_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/jp_only.txt) |
| [Lan](#copy-lan-1ac65711) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Lan.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Lan_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Lan_ip.mrs) | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Lan.txt) |
| [Microsoft](#copy-microsoft-c7bac469) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Microsoft.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Microsoft_domain.mrs) | — | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Microsoft.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Microsoft.txt) |
| [Nintendo](#copy-nintendo-0bee31ac) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Nintendo.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Nintendo_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Nintendo_ip.mrs) | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Nintendo.txt) |
| [OneDrive](#copy-onedrive-8a7a54d3) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/OneDrive.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/OneDrive_domain.mrs) | — | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/OneDrive.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/OneDrive.txt) |
| [PrivateTracker](#copy-privatetracker-2c036fa7) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/PrivateTracker.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/PrivateTracker_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/PrivateTracker_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/PrivateTracker.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/PrivateTracker.txt) |
| [Proxy](#copy-proxy-a68ee416) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Proxy.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Proxy_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Proxy_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Proxy.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Proxy.txt) |
| [Sony](#copy-sony-32b661b3) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Sony.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Sony_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Sony.txt) |
| [Speedtest](#copy-speedtest-22c0c8a6) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Speedtest.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Speedtest_domain.mrs) | — | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Speedtest.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Speedtest.txt) |
| [Steam](#copy-steam-f71a8503) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Steam.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Steam_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Steam_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Steam.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Steam.txt) |
| [SteamCN](#copy-steamcn-7b4b793c) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/SteamCN.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/SteamCN_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/SteamCN.txt) |
| [tailscale-derp](#copy-tailscale-derp-61458e01) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/tailscale-derp.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/tailscale-derp_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/tailscale-derp.txt) |
| [Telegram](#copy-telegram-acdd1e73) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/Telegram.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Telegram_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Telegram_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Telegram.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Telegram.txt) |
| [TikTok](#copy-tiktok-1bb6fcfb) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/TikTok.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/TikTok_domain.mrs) | — | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/TikTok.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/TikTok.txt) |
| [tracker](#copy-tracker-7ae4495c) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/tracker.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/tracker_domain.mrs) | — | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/tracker.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/tracker.txt) |
| [us_only](#copy-us_only-ac76bff5) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/us_only.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/us_only_domain.mrs) | — | — | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/us_only.txt) |
| [YouTube](#copy-youtube-fb7accff) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/surge/YouTube.list) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/YouTube_domain.mrs) | [MRS](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/YouTube_ip.mrs) | [LIST](https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/YouTube.list) | [TXT](https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/YouTube.txt) |

## 复制地址

展开对应规则，点击每个代码块右上角的 GitHub 原生复制图标，即可复制该格式的单条 Raw URL。每个代码块只放一个地址。

GitHub README 不运行自定义 JavaScript，因此这里使用原生代码块复制；上方表格链接用于直接查看文件。

<a name="copy-anthropic-c70eca6b"></a>
<details>
<summary><strong>anthropic</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/anthropic.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/anthropic_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/anthropic_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/anthropic.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/anthropic.txt
```

</details>

<a name="copy-apple-f223faa9"></a>
<details>
<summary><strong>Apple</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Apple.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Apple_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Apple_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Apple.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Apple.txt
```

</details>

<a name="copy-apple-cn-4f609836"></a>
<details>
<summary><strong>apple-cn</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/apple-cn.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/apple-cn_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/apple-cn.txt
```

</details>

<a name="copy-bilibili-94a36106"></a>
<details>
<summary><strong>BiliBili</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/BiliBili.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/BiliBili_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/BiliBili_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/BiliBili.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/BiliBili.txt
```

</details>

<a name="copy-category-ai-chat--cn-78cbd39a"></a>
<details>
<summary><strong>category-ai-chat-!cn</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-ai-chat-%21cn.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-ai-chat-%21cn_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-ai-chat-%21cn.txt
```

</details>

<a name="copy-category-ntp-f769d60c"></a>
<details>
<summary><strong>category-ntp</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-ntp.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-ntp_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-ntp.txt
```

</details>

<a name="copy-category-speedtest-cn-d3c61f2c"></a>
<details>
<summary><strong>category-speedtest-cn</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/category-speedtest-cn.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/category-speedtest-cn_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/category-speedtest-cn.txt
```

</details>

<a name="copy-chinamax-7cb9cda8"></a>
<details>
<summary><strong>ChinaMax</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/ChinaMax.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/ChinaMax_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/ChinaMax_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/ChinaMax.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/ChinaMax.txt
```

</details>

<a name="copy-custom_direct-f01bfe9b"></a>
<details>
<summary><strong>custom_direct</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/custom_direct.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/custom_direct_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/custom_direct_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/custom_direct.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/custom_direct.txt
```

</details>

<a name="copy-custom_proxy-1e9dc596"></a>
<details>
<summary><strong>custom_proxy</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/custom_proxy.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/custom_proxy_domain.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/custom_proxy.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/custom_proxy.txt
```

</details>

<a name="copy-docker-e6169e95"></a>
<details>
<summary><strong>Docker</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Docker.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Docker_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Docker.txt
```

</details>

<a name="copy-epic-a93d3898"></a>
<details>
<summary><strong>Epic</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Epic.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Epic_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Epic.txt
```

</details>

<a name="copy-github-f911e414"></a>
<details>
<summary><strong>GitHub</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/GitHub.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/GitHub_domain.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/GitHub.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/GitHub.txt
```

</details>

<a name="copy-globalmedia-c23e9780"></a>
<details>
<summary><strong>GlobalMedia</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/GlobalMedia.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/GlobalMedia_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/GlobalMedia_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/GlobalMedia.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/GlobalMedia.txt
```

</details>

<a name="copy-google-ce770667"></a>
<details>
<summary><strong>Google</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Google.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Google_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Google_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Google.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Google.txt
```

</details>

<a name="copy-googlefcm-99edb493"></a>
<details>
<summary><strong>GoogleFCM</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/GoogleFCM.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/GoogleFCM_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/GoogleFCM_ip.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/GoogleFCM.txt
```

</details>

<a name="copy-hk_balance-8bfbb23c"></a>
<details>
<summary><strong>hk_balance</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/hk_balance.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/hk_balance_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/hk_balance.txt
```

</details>

<a name="copy-jp_only-9ef4a483"></a>
<details>
<summary><strong>jp_only</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/jp_only.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/jp_only_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/jp_only.txt
```

</details>

<a name="copy-lan-1ac65711"></a>
<details>
<summary><strong>Lan</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Lan.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Lan_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Lan_ip.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Lan.txt
```

</details>

<a name="copy-microsoft-c7bac469"></a>
<details>
<summary><strong>Microsoft</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Microsoft.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Microsoft_domain.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Microsoft.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Microsoft.txt
```

</details>

<a name="copy-nintendo-0bee31ac"></a>
<details>
<summary><strong>Nintendo</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Nintendo.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Nintendo_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Nintendo_ip.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Nintendo.txt
```

</details>

<a name="copy-onedrive-8a7a54d3"></a>
<details>
<summary><strong>OneDrive</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/OneDrive.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/OneDrive_domain.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/OneDrive.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/OneDrive.txt
```

</details>

<a name="copy-privatetracker-2c036fa7"></a>
<details>
<summary><strong>PrivateTracker</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/PrivateTracker.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/PrivateTracker_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/PrivateTracker_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/PrivateTracker.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/PrivateTracker.txt
```

</details>

<a name="copy-proxy-a68ee416"></a>
<details>
<summary><strong>Proxy</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Proxy.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Proxy_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Proxy_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Proxy.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Proxy.txt
```

</details>

<a name="copy-sony-32b661b3"></a>
<details>
<summary><strong>Sony</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Sony.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Sony_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Sony.txt
```

</details>

<a name="copy-speedtest-22c0c8a6"></a>
<details>
<summary><strong>Speedtest</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Speedtest.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Speedtest_domain.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Speedtest.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Speedtest.txt
```

</details>

<a name="copy-steam-f71a8503"></a>
<details>
<summary><strong>Steam</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Steam.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Steam_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Steam_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Steam.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Steam.txt
```

</details>

<a name="copy-steamcn-7b4b793c"></a>
<details>
<summary><strong>SteamCN</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/SteamCN.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/SteamCN_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/SteamCN.txt
```

</details>

<a name="copy-tailscale-derp-61458e01"></a>
<details>
<summary><strong>tailscale-derp</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/tailscale-derp.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/tailscale-derp_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/tailscale-derp.txt
```

</details>

<a name="copy-telegram-acdd1e73"></a>
<details>
<summary><strong>Telegram</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/Telegram.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/Telegram_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/Telegram_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/Telegram.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/Telegram.txt
```

</details>

<a name="copy-tiktok-1bb6fcfb"></a>
<details>
<summary><strong>TikTok</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/TikTok.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/TikTok_domain.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/TikTok.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/TikTok.txt
```

</details>

<a name="copy-tracker-7ae4495c"></a>
<details>
<summary><strong>tracker</strong> · 4 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/tracker.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/tracker_domain.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/tracker.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/tracker.txt
```

</details>

<a name="copy-us_only-ac76bff5"></a>
<details>
<summary><strong>us_only</strong> · 3 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/us_only.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/us_only_domain.mrs
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/us_only.txt
```

</details>

<a name="copy-youtube-fb7accff"></a>
<details>
<summary><strong>YouTube</strong> · 5 个格式文件</summary>

**Surge** · `RULE-SET`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/surge/YouTube.list
```

**Mihomo 域名** · `domain / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/domain/YouTube_domain.mrs
```

**Mihomo IP** · `ipcidr / mrs`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/ip/YouTube_ip.mrs
```

**Mihomo 补充** · `classical / text · 补充规则`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mihomo/classical/YouTube.list
```

**MosDNS** · `domain_set`

```text
https://raw.githubusercontent.com/ihnic/Rule/main/mosdns/YouTube.txt
```

</details>

---

此页由 `readme.py` 扫描现有产物自动生成。更新页面结构请修改生成器；规则内容请修改对应来源。
