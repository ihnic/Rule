"""Generate the rule index and individually copyable Raw URLs for GitHub."""

from hashlib import sha256
from html import escape
from pathlib import Path
import re
from urllib.parse import quote


# Verified against origin and its advertised default branch on 2026-11-17.
RAW_BASE_URL = "https://raw.githubusercontent.com/ihnic/Rule/main"
FORMATS = (
    ("surge", "Surge", "surge", "", (".list",)),
    ("domain", "Mihomo 域名", "mihomo/domain", "_domain", (".mrs", ".list")),
    ("ip", "Mihomo IP", "mihomo/ip", "_ip", (".mrs", ".list")),
    ("classical", "Mihomo 补充", "mihomo/classical", "", (".list",)),
    ("mosdns", "MosDNS", "mosdns", "", (".txt",)),
)


def _collect_files(root):
    """Select existing artifacts, preferring MRS over its duplicate text input."""
    rules = {}
    for kind, _, directory, name_suffix, extensions in FORMATS:
        folder = root / directory
        if not folder.is_dir():
            continue
        for extension in extensions:
            for artifact in sorted(folder.glob(f"*{extension}")):
                if not artifact.is_file():
                    continue
                name = artifact.stem
                if name_suffix and name.endswith(name_suffix):
                    name = name[:-len(name_suffix)]
                formats = rules.setdefault(name, {})
                formats.setdefault(kind, artifact.relative_to(root))
    return rules


def _raw_url(path):
    return f"{RAW_BASE_URL}/{quote(path.as_posix(), safe='/')}"


def _copy_anchor(name):
    readable = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-") or "rule"
    # Keep links distinct even for names differing only in case or punctuation.
    identifier = sha256(name.encode("utf-8")).hexdigest()[:8]
    return f"copy-{readable}-{identifier}"


def _format_label(kind, path):
    if kind in ("domain", "ip"):
        behavior = "domain" if kind == "domain" else "ipcidr"
        file_format = "mrs" if path.suffix == ".mrs" else "text"
        return f"{behavior} / {file_format}"
    return {
        "surge": "RULE-SET",
        "classical": "classical / text · 补充规则",
        "mosdns": "domain_set",
    }[kind]


def generate_readme(path="README.md", root="."):
    """Scan ``root`` and write the index to ``path`` (relative to root by default).

    Pass an absolute ``path`` to preview the generated page without replacing
    the repository README. No Git commands or network requests run here.
    """
    root = Path(root).resolve()
    target = Path(path)
    if not target.is_absolute():
        target = root / target
    rules = _collect_files(root)
    names = sorted(rules, key=lambda name: (name.casefold(), name))
    docs_url = "docs/conversion.md"
    lines = [
        "# Rule · 规则集",
        "",
        "适用于 Surge、Mihomo 与 MosDNS。每行对应一组规则，索引中的订阅链接均为 `main` 分支的 Raw 地址。",
        "",
        f"[规则索引](#规则索引) · [复制地址](#复制地址) · [转换语义与配置示例]({docs_url})",
        "",
        "来源或转换逻辑提交后自动更新；上游每 15 分钟检查一次，实际运行时间以 GitHub Actions 调度为准。",
        "",
        "需要清掉历史规则和旧缓存时，可在 Actions 中手动运行[规则清理并全量重建](https://github.com/ihnic/Rule/actions/workflows/rebuild_rules.yml)。全部来源重建成功后，才整体替换旧产物。",
        "",
        "- **Surge**：使用 `RULE-SET`；**MosDNS**：使用 `domain_set`，仅包含域名与关键词。",
        "- **Mihomo**：域名与 IP 优先提供 MRS；补充文件使用 `classical / text`，包含关键词、ASN、进程等规则，**不是完整全集**。请一起引用需要的分类。",
        "- **IP 解析**：Mihomo IP MRS 不保存逐条 `no-resolve`；需要禁止主动解析时，在引用处添加 `RULE-SET,集合名,策略,no-resolve`。",
        "",
        "## 规则索引",
        "",
        f"共 **{len(names)}** 组规则。点击格式查看 Raw 文件；点击规则名称前往该组的复制区。`—` 表示没有此类文件。",
        "",
        "| 规则 | Surge | Mihomo 域名 | Mihomo IP | Mihomo 补充 | MosDNS |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |",
    ]
    for name in names:
        display_name = escape(name).replace("|", "&#124;").replace("[", "&#91;").replace("]", "&#93;")
        cells = [f"[{display_name}](#{_copy_anchor(name)})"]
        for kind, _, _, _, _ in FORMATS:
            artifact = rules[name].get(kind)
            cells.append(f"[{artifact.suffix[1:].upper()}]({_raw_url(artifact)})" if artifact else "—")
        lines.append("| " + " | ".join(cells) + " |")
    lines.extend([
        "",
        "## 复制地址",
        "",
        "展开对应规则，点击每个代码块右上角的 GitHub 原生复制图标，即可复制该格式的单条 Raw URL。每个代码块只放一个地址。",
        "",
        "GitHub README 不运行自定义 JavaScript，因此这里使用原生代码块复制；上方表格链接用于直接查看文件。",
        "",
    ])
    for name in names:
        lines.extend([
            f'<a name="{_copy_anchor(name)}"></a>',
            "<details>",
            f"<summary><strong>{escape(name)}</strong> · {len(rules[name])} 个格式文件</summary>",
            "",
        ])
        for kind, title, _, _, _ in FORMATS:
            artifact = rules[name].get(kind)
            if artifact is None:
                continue
            lines.extend([
                f"**{title}** · `{_format_label(kind, artifact)}`",
                "",
                "```text",
                _raw_url(artifact),
                "```",
                "",
            ])
        lines.extend(["</details>", ""])
    lines.extend([
        "---",
        "",
        "此页由 `readme.py` 扫描现有产物自动生成。更新页面结构请修改生成器；规则内容请修改对应来源。",
        "",
    ])
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines), encoding="utf-8")
    return target
