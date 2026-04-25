import requests
import re
import os
import subprocess
import hashlib
import json

# --- 配置区 ---
RULES_FILE = "rules.txt"
CUSTOM_DIR = "custom"
VERSION_FILE = "versions.json"
MIHOMO_BIN = "./mihomo-core" # 指向 Linux 版内核
BASE_DIR = "."

# 输出目录结构
DIRS = [
    "mihomo/domain", "mihomo/ip", "mihomo/classical",
    "surge", "mosdns"
]

def get_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_versions():
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def setup_dirs():
    for d in DIRS:
        os.makedirs(d, exist_ok=True)

def parse_rules(content):
    """原子化解析：将各种格式统一拆解为 domain, ip, classical"""
    res = {"domain": [], "ip": [], "classical": []}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        clean = re.sub(r'^-\s*', '', line)

        # 匹配逻辑
        if 'DOMAIN-SUFFIX' in clean or clean.startswith('+.'):
            d = clean.split(',')[-2] if ',' in clean else clean.replace('+.','')
            res["domain"].append(d)
        elif 'DOMAIN,' in clean:
            res["domain"].append(f"FULL:{clean.split(',')[1]}")
        elif 'IP-CIDR' in clean:
            res["ip"].append(clean.split(',')[1])
        elif 'DOMAIN-KEYWORD' in clean or 'keyword:' in clean:
            k = clean.split(',')[1] if ',' in clean else clean.replace('keyword:','')
            res["classical"].append(f"DOMAIN-KEYWORD,{k}")
        else:
            res["classical"].append(clean)
    return res

def write_outputs(name, data):
    """一源三发：分发到不同平台的文件夹"""
    # 1. Surge 导出 (.list)
    with open(f"surge/{name}.list", 'w', encoding='utf-8') as f:
        for d in data["domain"]:
            f.write(f"DOMAIN,{d.replace('FULL:','')}\n" if "FULL:" in d else f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip}\n")
        for cls in data["classical"]: f.write(f"{cls}\n")

    # 2. MosDNS 导出 (.txt)
    with open(f"mosdns/{name}.txt", 'w', encoding='utf-8') as f:
        for d in data["domain"]:
            f.write(f"full:{d.replace('FULL:','')}\n" if "FULL:" in d else f"domain:{d}\n")
        for cls in data["classical"]:
            if "DOMAIN-KEYWORD" in cls: f.write(f"keyword:{cls.split(',')[1]}\n")

    # 3. Mihomo 导出与编译
    for cat in ["domain", "ip", "classical"]:
        items = data[cat]
        if not items: continue
        txt_path = f"mihomo/{cat}/{name}.list"
        with open(txt_path, 'w', encoding='utf-8') as f:
            for item in items:
                if cat == "domain":
                    f.write(f"{item.replace('FULL:','')}\n" if "FULL:" in item else f"+.{item}\n")
                else: f.write(f"{item}\n")
        
        # 编译二进制 MRS (仅 domain 和 ip)
        if cat in ["domain", "ip"]:
            mrs_path = txt_path.replace(".list", ".mrs")
            bh = "ipcidr" if cat == "ip" else "domain"
            subprocess.run([MIHOMO_BIN, "convert-ruleset", bh, "text", txt_path, mrs_path])

def generate_readme():
    """生成全平台合并索引 README"""
    readme_path = "README.md"
    def clean_name(f):
        # 先切后缀，再切类型标识
        n = re.sub(r'\.(list|mrs|txt)$', '', f, flags=re.IGNORECASE)
        n = re.sub(r'_(domain|ip|classical)$', '', n, flags=re.IGNORECASE)
        return n

    sections = {"mrs": [], "surge": [], "mosdns": [], "cls": []}

    # 扫描
    for cat in ['domain', 'ip']:
        p = f"mihomo/{cat}"
        if os.path.exists(p):
            for f in os.listdir(p):
                if f.endswith(".mrs"):
                    sections["mrs"].append({"n": clean_name(f), "t": cat, "f": f, "p": f"./mihomo/{cat}/{f}"})
    
    if os.path.exists("surge"):
        for f in os.listdir("surge"):
            if f.endswith(".list"):
                sections["surge"].append({"n": clean_name(f), "f": f, "p": f"./surge/{f}"})

    if os.path.exists("mosdns"):
        for f in os.listdir("mosdns"):
            if f.endswith(".txt"):
                sections["mosdns"].append({"n": clean_name(f), "f": f, "p": f"./mosdns/{f}"})

    if os.path.exists("mihomo/classical"):
        for f in os.listdir("mihomo/classical"):
            if f.endswith(".list"):
                sections["cls"].append({"n": clean_name(f), "f": f, "p": f"./mihomo/classical/{f}"})

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# 📂 规则集索引\n\n> 自动化同步流水线，每天 03:00 更新。\n\n")

        # MRS 表格
        f.write("## 🛠 MRS 格式 (Mihomo)\n| 规则名 | 类型 | 文件名 | 相对路径 |\n| :--- | :--- | :--- | :--- |\n")
        for i in sorted(sections["mrs"], key=lambda x: (x['n'], x['t'])):
            f.write(f"| {i['n']} | {i['t']} | {i['f']} | `{i['p']}` |\n")

        # Surge 表格
        f.write("\n## 🛠 Surge 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
        for i in sorted(sections["surge"], key=lambda x: x['n']):
            f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")

        # MosDNS 表格
        f.write("\n## 🛠 MosDNS 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
        for i in sorted(sections["mosdns"], key=lambda x: x['n']):
            f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")

        f.write(f"\n\n> 最后更新: {subprocess.getoutput('date')}")

def main():
    setup_dirs()
    versions = load_versions()
    new_versions = {}
    processed_names = []

    # 1. 处理 Custom
    if os.path.exists(CUSTOM_DIR):
        for f in os.listdir(CUSTOM_DIR):
            if f.endswith(".txt"):
                name = f.replace(".txt", "")
                processed_names.append(name)
                with open(os.path.join(CUSTOM_DIR, f), 'r', encoding='utf-8') as file:
                    content = file.read()
                    h = get_hash(content)
                    new_versions[name] = h
                    if versions.get(name) != h:
                        write_outputs(name, parse_rules(content))

    # 2. 处理 Rules.txt
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"): continue
                name = url.split('/')[-1].replace('.list','').replace('.txt','')
                processed_names.append(name)
                try:
                    r = requests.get(url, timeout=15)
                    h = get_hash(r.text)
                    new_versions[name] = h
                    if versions.get(name) != h:
                        write_outputs(name, parse_rules(r.text))
                except: print(f"Error fetching {url}")

    save_versions(new_versions)
    generate_readme()

if __name__ == "__main__":
    main()