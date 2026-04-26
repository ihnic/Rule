import requests
import re
import os
import subprocess
import hashlib
import json
import shutil

# --- 配置区 ---
RULES_FILE = "rules.txt"
CUSTOM_DIR = "custom"
VERSION_FILE = "versions.json"
MIHOMO_BIN = "./mihomo-core"
DIRS = ["mihomo/domain", "mihomo/ip", "mihomo/classical", "surge", "mosdns"]

FORCE_REWRITE = os.getenv("FORCE_UPDATE") == "true"

def get_raw_url(url):
    if "github.com" in url and "/blob/" in url:
        return url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    return url

def get_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_versions():
    if FORCE_REWRITE: return {}
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
    if FORCE_REWRITE:
        print("🗑️ [强制模式] 清空旧目录...")
        for d in ["mihomo", "surge", "mosdns"]:
            if os.path.exists(d): shutil.rmtree(d)
    for d in DIRS: os.makedirs(d, exist_ok=True)

def parse_rules(content):
    if not content or "<!DOCTYPE html>" in content or "<html" in content:
        return None
    res = {"domain": [], "full": [], "ip": [], "classical": []}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        raw_line = re.sub(r'^-\s*', '', line)
        parts = [p.strip() for p in raw_line.split(',')]
        tag = parts[0].upper()
        try:
            if tag == 'DOMAIN-SUFFIX': res["domain"].append(parts[1])
            elif tag == 'DOMAIN': res["full"].append(parts[1])
            elif tag in ['IP-CIDR', 'IP-CIDR6']: res["ip"].append(parts[1])
            elif tag in ['PROCESS-NAME', 'DOMAIN-KEYWORD']: res["classical"].append(f"{tag},{parts[1]}")
            elif raw_line.startswith('+.'): res["domain"].append(raw_line.replace('+.',''))
            elif len(parts) == 1 and '.' in raw_line: res["full"].append(raw_line)
        except: continue
    return res

def write_outputs(name, data):
    if not data: return
    # Surge
    with open(f"surge/{name}.list", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"DOMAIN,{d}\n")
        for d in data["domain"]: f.write(f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip},no-resolve\n")
        for cls in data["classical"]: f.write(f"{cls}\n")
    # MosDNS
    with open(f"mosdns/{name}.txt", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"full:{d}\n")
        for d in data["domain"]: f.write(f"domain:{d}\n")
    # Mihomo
    if data["domain"] or data["full"]:
        p = f"mihomo/domain/{name}_domain.list"
        with open(p, 'w', encoding='utf-8') as f:
            for d in data["full"]: f.write(f"{d}\n")
            for d in data["domain"]: f.write(f"+.{d}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "domain", "text", p, p.replace(".list", ".mrs")], capture_output=True)
    if data["ip"]:
        p = f"mihomo/ip/{name}_ip.list"
        with open(p, 'w', encoding='utf-8') as f:
            for ip in data["ip"]: f.write(f"{ip}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "ipcidr", "text", p, p.replace(".list", ".mrs")], capture_output=True)
    if data["classical"]:
        with open(f"mihomo/classical/{name}.list", 'w', encoding='utf-8') as f:
            f.write("\n".join(data["classical"]))

def generate_readme():
    """按 Nic 哥要求的权重排序并隐藏重复 list"""
    readme_path = "README.md"
    
    # 定义 Mihomo 类型的显示顺序权重
    type_weight = {"domain": 1, "ip": 2, "classical": 3}
    
    # 聚合格式: { rule_name: { type: { 'mrs': path, 'list': path } } }
    mihomo_map = {}

    for cat in ['domain', 'ip', 'classical']:
        p = f"mihomo/{cat}"
        if not os.path.exists(p): continue
        for f in os.listdir(p):
            ext = 'mrs' if f.endswith('.mrs') else 'list'
            if not f.endswith(('.mrs', '.list')): continue
            
            # 提取 Apple 这种核心名
            name = re.sub(r'(_domain|_ip)?\.(list|mrs)$', '', f, flags=re.IGNORECASE)
            
            if name not in mihomo_map: mihomo_map[name] = {}
            if cat not in mihomo_map[name]: mihomo_map[name][cat] = {}
            
            mihomo_map[name][cat][ext] = f"./mihomo/{cat}/{f}"

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# 📂 规则集索引\n\n## 🛠 Mihomo 格式\n| 规则名 | 类型 | 文件名 | 相对路径 |\n| :--- | :--- | :--- | :--- |\n")
        
        for name in sorted(mihomo_map.keys()):
            # 按照权重排序类型 (domain -> ip -> classical)
            sorted_cats = sorted(mihomo_map[name].keys(), key=lambda x: type_weight.get(x, 99))
            
            for cat in sorted_cats:
                files = mihomo_map[name][cat]
                # 优先级逻辑：如果该 cat 下有 mrs，就只显示 mrs；否则显示 list
                if 'mrs' in files:
                    target_ext = 'mrs'
                    path = files['mrs']
                else:
                    target_ext = 'list'
                    path = files['list']
                
                filename = path.split('/')[-1]
                f.write(f"| {name} | {cat} | {filename} | `{path}` |\n")

        # Surge & MosDNS 保持原样
        for platform in ["surge", "mosdns"]:
            f.write(f"\n## 🛠 {platform.capitalize()} 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
            if os.path.exists(platform):
                for file in sorted(os.listdir(platform)):
                    if file.endswith(('.list', '.txt')):
                        n = re.sub(r'\.(list|txt)$', '', file)
                        f.write(f"| {n} | {file} | `./{platform}/{file}` |\n")

def main():
    setup_dirs()
    versions = load_versions()
    new_versions = {}
    if os.path.exists(CUSTOM_DIR):
        for f in os.listdir(CUSTOM_DIR):
            if f.endswith(".txt"):
                name = f.replace(".txt", "").replace("@", "-")
                with open(os.path.join(CUSTOM_DIR, f), 'r', encoding='utf-8') as file:
                    content = file.read()
                    h = get_hash(content); new_versions[name] = h
                    if versions.get(name) != h or FORCE_REWRITE: write_outputs(name, parse_rules(content))
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"): continue
                raw_url = get_raw_url(url)
                name = url.split('/')[-1].replace('.list','').replace('.txt','').replace('@', '-')
                try:
                    r = requests.get(raw_url, timeout=15)
                    h = get_hash(r.text); new_versions[name] = h
                    if versions.get(name) != h or FORCE_REWRITE: write_outputs(name, parse_rules(r.text))
                except: pass
    save_versions(new_versions)
    generate_readme()

if __name__ == "__main__":
    main()
