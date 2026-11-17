import requests
import re
import os
import subprocess
import hashlib
import json
import argparse
import ipaddress
import tempfile
from pathlib import Path
from urllib.parse import quote, urlparse

from readme import generate_readme

# --- 配置区 ---
RULES_FILE = "rules.txt"
CUSTOM_DIR = "custom"
VERSION_FILE = "versions.json"
MIHOMO_BIN = os.getenv("MIHOMO_BIN", "./mihomo-core")
GEOSITE_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/classical/{tag}.list"
DIRS = ["mihomo/domain", "mihomo/ip", "mihomo/classical", "surge", "mosdns"]

FORCE_REWRITE = os.getenv("FORCE_UPDATE") == "true"

def get_raw_url(url):
    if "github.com" in url and "/blob/" in url:
        return url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    return url

def get_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_versions():
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_versions(versions):
    with open(VERSION_FILE, 'w', encoding='utf-8') as f:
        json.dump(versions, f, indent=4, ensure_ascii=False)

def setup_dirs():
    if os.path.isfile("mihomo"):
        try: os.remove("mihomo")
        except: pass
    for d in DIRS: os.makedirs(d, exist_ok=True)

def fetch_text(url):
    response = requests.get(get_raw_url(url), timeout=30)
    response.raise_for_status()
    content = response.text
    if not any(line.strip() and not line.lstrip().startswith(('#', '//', 'payload:'))
               for line in content.splitlines()):
        raise ValueError(f'远程规则源为空，保留旧规则: {url}')
    return content


def load_geosite(tag):
    # The domain export omits keywords/regex. Always inspect the classical export.
    if not re.fullmatch(r"[a-z0-9][a-z0-9_!@.\-]*", tag):
        raise ValueError(f"无效的 geosite 标签: {tag}")
    content = fetch_text(GEOSITE_URL.format(tag=quote(tag, safe="")))
    if not content.strip():
        raise ValueError(f"geosite:{tag} 返回空内容")
    return content


def empty_rules():
    return {key: [] for key in ("domain", "full", "ip", "ip_rules", "classical")}


def merge_rules(target, source):
    for key in target:
        target[key] = list(dict.fromkeys(target[key] + source[key]))
    return target


def validate_parameters(tag, parts):
    if len(parts) < 2 or not parts[1]:
        raise ValueError('匹配值不能为空')
    extras = parts[2:]
    # Some existing custom inputs contain a built-in policy. Rule-set outputs
    # deliberately leave policy selection to the consuming configuration.
    if extras and extras[0].upper() in ('DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'PROXY'):
        extras = extras[1:]
    allowed = ['no-resolve'] if tag in ('IP-CIDR', 'IP-CIDR6', 'IP-ASN') else []
    if extras and extras != allowed:
        raise ValueError(f'不支持的规则参数: {",".join(extras)}')


def parse_rules(content, geosite_loader=None, _stack=()):
    if re.search(r"<!doctype html|<html", content, re.IGNORECASE):
        raise ValueError("规则源返回了 HTML")
    geosite_loader = geosite_loader or load_geosite
    res = empty_rules()
    for number, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        raw_line = re.sub(r'^-\s+', '', line)
        if len(raw_line) >= 2 and raw_line[0] == raw_line[-1] and raw_line[0] in "\"'":
            raw_line = raw_line[1:-1]
        raw_line = re.split(r"\s+#", raw_line, maxsplit=1)[0].strip()
        parts = [p.strip() for p in raw_line.split(',')]
        tag = parts[0].upper()
        try:
            # These are input aliases, not strings to copy into every platform.
            if len(parts) == 1 and ':' in raw_line:
                prefix, value = raw_line.split(':', 1)
                aliases = {"domain": "DOMAIN-SUFFIX", "full": "DOMAIN",
                           "keyword": "DOMAIN-KEYWORD", "geosite": "GEOSITE"}
                if prefix.lower() in aliases:
                    tag = aliases[prefix.lower()]
                    parts = [tag, value.strip()]
            if tag in ('GEOSITE', 'DOMAIN-SUFFIX', 'DOMAIN', 'IP-CIDR', 'IP-CIDR6',
                       'IP-ASN', 'PROCESS-NAME', 'DOMAIN-KEYWORD'):
                validate_parameters(tag, parts)
            if tag == 'GEOSITE':
                label = parts[1].lower()
                if not re.fullmatch(r"[a-z0-9][a-z0-9_!@.\-]*", label):
                    raise ValueError(f'无效的 geosite 标签: {label}')
                if label in _stack:
                    raise ValueError(f"循环 geosite 引用: {' -> '.join(_stack + (label,))}")
                expanded = parse_rules(geosite_loader(label), geosite_loader, _stack + (label,))
                merge_rules(res, expanded)
            elif tag in ('DOMAIN-SUFFIX', 'DOMAIN'):
                value = parts[1].lower().rstrip('.')
                if not re.fullmatch(r"[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*", value):
                    raise ValueError(f"不支持的域名表达式: {parts[1]}")
                res['domain' if tag == 'DOMAIN-SUFFIX' else 'full'].append(value)
            elif tag in ('IP-CIDR', 'IP-CIDR6'):
                network = ipaddress.ip_network(parts[1], strict=False)
                if tag == 'IP-CIDR6' and network.version != 6:
                    raise ValueError('IP-CIDR6 必须使用 IPv6 网段')
                value = str(network)
                res['ip'].append(value)
                ip_tag = 'IP-CIDR6' if network.version == 6 else 'IP-CIDR'
                options = ',no-resolve' if 'no-resolve' in parts[2:] else ''
                res['ip_rules'].append(f'{ip_tag},{value}{options}')
            elif tag == 'IP-ASN':
                asn = int(parts[1])
                if not 0 <= asn <= 4294967295:
                    raise ValueError('ASN 超出 32 位范围')
                options = ',no-resolve' if 'no-resolve' in parts[2:] else ''
                res['classical'].append(f'IP-ASN,{asn}{options}')
            elif tag in ('PROCESS-NAME', 'DOMAIN-KEYWORD'):
                value = parts[1]
                if tag == 'DOMAIN-KEYWORD' and any(char.isspace() for char in value):
                    raise ValueError('域名关键词不能包含空白')
                res['classical'].append(f'{tag},{value}')
            elif raw_line.startswith('+.'):
                merge_rules(res, parse_rules(f'DOMAIN-SUFFIX,{raw_line[2:]}', geosite_loader))
            elif len(parts) == 1 and re.fullmatch(r"[a-zA-Z0-9_\-]+(?:\.[a-zA-Z0-9_\-]+)+\.?", raw_line):
                res['full'].append(raw_line.lower().rstrip('.'))
            else:
                raise ValueError(f'不能在三个目标中按已支持的语义转换: {raw_line}')
        except (ValueError, IndexError) as exc:
            raise ValueError(f'第 {number} 行 ({raw_line}): {exc}') from exc
    for key in res:
        res[key] = list(dict.fromkeys(res[key]))
    return res


def output_paths(name):
    return [f'surge/{name}.list', f'mosdns/{name}.txt',
            f'mihomo/domain/{name}_domain.list', f'mihomo/domain/{name}_domain.mrs',
            f'mihomo/ip/{name}_ip.list', f'mihomo/ip/{name}_ip.mrs',
            f'mihomo/classical/{name}.list']


def mosdns_keyword(value):
    # MosDNS normalizes keyword patterns with TrimDot; Mihomo keeps a literal
    # trailing dot. A literal regexp preserves that substring boundary.
    if value.endswith('.'):
        escaped = ''.join('\\' + char if char in r'\.+*?()|[]{}^$' else char for char in value)
        return f'regexp:(?i){escaped}'
    return f'keyword:{value}'


def text_outputs(name, data):
    surge = ([f'DOMAIN,{d}' for d in data['full']]
             + [f'DOMAIN-SUFFIX,{d}' for d in data['domain']]
             + data['ip_rules'] + data['classical'])
    mosdns = ([f'full:{d}' for d in data['full']]
              + [f'domain:{d}' for d in data['domain']]
              + [mosdns_keyword(rule.split(',', 1)[1]) for rule in data['classical']
                 if rule.startswith('DOMAIN-KEYWORD,')])
    outputs = {f'surge/{name}.list': surge, f'mosdns/{name}.txt': mosdns}
    if data['domain'] or data['full']:
        outputs[f'mihomo/domain/{name}_domain.list'] = data['full'] + [f'+.{d}' for d in data['domain']]
    if data['ip']:
        outputs[f'mihomo/ip/{name}_ip.list'] = data['ip']
    if data['classical']:
        outputs[f'mihomo/classical/{name}.list'] = data['classical']
    return {path: ''.join(f'{line}\n' for line in lines) for path, lines in outputs.items()}


def publish_outputs(name, staging, generated):
    # Keep old files until every replacement succeeds, including when deleting
    # a rule group whose source has been removed.
    backup = staging / 'previous'
    backed_up, installed = [], []
    try:
        for relative in output_paths(name):
            target = Path(relative)
            if target.exists():
                if not target.is_file():
                    raise IsADirectoryError(str(target))
                previous = backup / relative
                previous.parent.mkdir(parents=True, exist_ok=True)
                os.replace(target, previous)
                backed_up.append(relative)
        for relative in generated:
            target = Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging / relative, target)
            installed.append(relative)
    except OSError:
        for relative in installed:
            Path(relative).unlink(missing_ok=True)
        for relative in backed_up:
            os.replace(backup / relative, relative)
        raise


def remove_outputs(name):
    with tempfile.TemporaryDirectory(prefix='.rules-', dir='.') as temporary:
        publish_outputs(name, Path(temporary), [])


def write_outputs(name, data):
    if not data: return
    outputs = text_outputs(name, data)
    # Publish a group only after every required MRS has compiled successfully.
    with tempfile.TemporaryDirectory(prefix='.rules-', dir='.') as temporary:
        staging = Path(temporary)
        for relative, content in outputs.items():
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding='utf-8')
        generated = list(outputs)
        for kind, behavior in (('domain', 'domain'), ('ip', 'ipcidr')):
            relative = f'mihomo/{kind}/{name}_{kind}.list'
            if relative not in outputs:
                continue
            source = staging / relative
            binary = source.with_suffix('.mrs')
            subprocess.run([MIHOMO_BIN, 'convert-ruleset', behavior, 'text', str(source), str(binary)],
                           capture_output=True, text=True, check=True)
            if not binary.is_file() or binary.stat().st_size == 0:
                raise RuntimeError(f'Mihomo 未生成有效产物: {relative}')
            generated.append(str(Path(relative).with_suffix('.mrs')))
        publish_outputs(name, staging, generated)


def main(only=None):
    setup_dirs()
    versions = load_versions()
    new_versions = dict(versions)
    sources = {}
    selected = set(only) if only else None

    def add_source(name, origin, remote=False):
        if selected is None or name in selected:
            sources.setdefault(name, []).append((origin, remote))

    if os.path.exists(CUSTOM_DIR):
        for f in sorted(os.listdir(CUSTOM_DIR)):
            if f.endswith(".txt"):
                name = f[:-4].replace("@", "-")
                add_source(name, os.path.join(CUSTOM_DIR, f))
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"): continue
                name = re.sub(r'\.(list|txt)$', '', Path(urlparse(url).path).name).replace('@', '-')
                add_source(name, url, remote=True)

    # Refetch dependencies on every run, including when the custom file is unchanged.
    geosite_cache = {}

    def geosite_loader(tag):
        if tag not in geosite_cache:
            geosite_cache[tag] = load_geosite(tag)
        return geosite_cache[tag]

    converter_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    compiler = Path(MIHOMO_BIN)
    compiler_hash = hashlib.sha256(compiler.read_bytes()).hexdigest() if compiler.is_file() else None
    errors = []
    if selected:
        for name in sorted(selected - sources.keys()):
            errors.append(f'{name}: 没有找到规则源')
    for name, inputs in sources.items():
        try:
            data = empty_rules()
            for origin, remote in inputs:
                content = fetch_text(origin) if remote else Path(origin).read_text(encoding='utf-8')
                merge_rules(data, parse_rules(content, geosite_loader))
            signature = get_hash(json.dumps({'converter': converter_hash, 'compiler': compiler_hash, 'data': data},
                                            sort_keys=True, ensure_ascii=False))
            expected = set(text_outputs(name, data))
            expected.update(str(Path(p).with_suffix('.mrs')) for p in list(expected)
                            if p.startswith(('mihomo/domain/', 'mihomo/ip/')))
            if (FORCE_REWRITE or versions.get(name) != signature
                    or any(not Path(path).is_file() for path in expected)
                    or any(Path(path).exists() for path in set(output_paths(name)) - expected)):
                write_outputs(name, data)
                print(f'✅ {name}: 已生成 Surge / Mihomo / MosDNS 规则')
            else:
                print(f'⏭️ {name}: 内容与转换器均未变化')
            new_versions[name] = signature
            ip_count = len(data['ip']) + sum(rule.startswith('IP-ASN,') for rule in data['classical'])
            process_count = sum(rule.startswith('PROCESS-NAME,') for rule in data['classical'])
            if ip_count or process_count:
                print(f'ℹ️ {name}: MosDNS domain_set 不承载 {ip_count} 条 IP/ASN 与 {process_count} 条进程规则')
        except (ValueError, OSError, requests.RequestException, subprocess.SubprocessError, RuntimeError) as exc:
            detail = getattr(exc, 'stderr', None) or str(exc)
            errors.append(f'{name}: {detail}')
            print(f'❌ {name}: 转换失败，保留该组原产物和版本记录。{detail}')
    if selected is None:
        for name in sorted(versions.keys() - sources.keys()):
            try:
                remove_outputs(name)
                new_versions.pop(name)
                print(f'🗑️ {name}: 规则源已移除，清理旧产物与版本记录')
            except OSError as exc:
                errors.append(f'{name}: 清理旧产物失败: {exc}')
    save_versions(new_versions)
    generate_readme()
    if errors:
        print(f'❌ {len(errors)} 个规则集未完成: ' + '; '.join(errors))
        return 1
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='按各平台语义转换规则集')
    parser.add_argument('--only', nargs='+', help='只更新指定规则集，例如 anthropic category-ntp')
    raise SystemExit(main(parser.parse_args().only))
