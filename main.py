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
MIHOMO_BIN = "./mihomo-core"
DIRS = ["mihomo/domain", "mihomo/ip", "mihomo/classical", "surge", "mosdns"]

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
    # 修复：使用 Python 语法删除同名文件冲突
    if os.path.isfile("mihomo"):
        try:
            os.remove("mihomo")
        except: pass
    for d in DIRS:
        os.makedirs(d, exist_ok=True)

def parse_rules(content):
    """精准解析逻辑：彻底解决前缀重复和逗号残留问题"""
    res = {"domain": [], "full": [], "ip": [], "classical": []}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        
        # 处理可能带 - 前缀的行
        raw_line = re.sub(r'^-\s*', '', line)
        parts = raw_line.split(',')
        tag = parts[0].strip().upper()
        
        try:
            # 1. 域名后缀匹配 (DOMAIN-SUFFIX)
            if tag == 'DOMAIN-SUFFIX':
                res["domain"].append(parts[1].strip())
            # 2. 域名完全匹配 (DOMAIN)
            elif tag == 'DOMAIN':
                res["full"].append(parts[1].strip())
            # 3. IP 匹配 (IP-CIDR / IP-CIDR6)
            elif tag in ['IP-CIDR', 'IP-CIDR6']:
                res["ip"].append(parts[1].strip())
            # 4. 进程名匹配 (PROCESS-NAME)
            elif tag == 'PROCESS-NAME':
                res["classical"].append(f"PROCESS-NAME,{parts[1].strip()}")
            # 5. 关键字匹配 (DOMAIN-KEYWORD)
            elif tag == 'DOMAIN-KEYWORD':
                res["classical"].append(f"DOMAIN-KEYWORD,{parts[1].strip()}")
            # 6. 处理 Mihomo 特有简写
            elif raw_line.startswith('+.'):
                res["domain"].append(raw_line.replace('+.','').strip())
            # 7. 处理纯域名（默认为 FULL）
            elif len(parts) == 1 and '.' in raw_line and not raw_line.startswith('+'):
                res["full"].append(raw_line)
        except IndexError:
            continue
    return res

def write_outputs(name, data):
    """分发到不同平台的文件夹"""
    # 1. Surge 导出 (.list)
    with open(f"surge/{name}.list", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"DOMAIN,{d}\n")
        for d in data["domain"]: f.write(f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip},no-resolve\n")
        for cls in data["classical"]: f.write(f"{cls}\n")

    # 2. MosDNS 导出 (.txt)
    with open(f"mosdns/{name}.txt", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"full:{d}\n")
        for d in data["domain"]: f.write(f"domain:{d}\n")
        # 针对 MosDNS 提取 keyword
        for cls in data["classical"]:
            if cls.startswith("DOMAIN-KEYWORD"):
                f.write(f"keyword:{cls.split(',')[1]}\n")

    # 3. Mihomo 导出与编译
    # Domain (MRS)
    if data["domain"] or data["full"]:
        txt_path = f"mihomo/domain/{name}.list"
        with open(txt_path, 'w', encoding='utf-8') as f:
            for d in data["full"]: f.write(f"{d}\n")
            for d in data["domain"]: f.write(f"+.{d}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "domain", "text", txt_path, txt_path.replace(".list", ".mrs")], capture_output=True)

    # IP (MRS)
    if data["ip"]:
        txt_path = f"mihomo/ip/{name}.list"
        with open(txt_path, 'w', encoding='utf-8') as f:
            for ip in data["ip"]: f.write(f"{ip}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "ipcidr", "text", txt_path, txt_path.replace(".list", ".mrs")], capture_output=True)

    # Classical (Text)
    if data["classical"]:
        with open(f"mihomo/classical/{name}.list", 'w', encoding='utf-8') as f:
            f.write("\n".join(data["classical"]))

def generate_readme():
    readme_path = "README.md"
    def clean_name(f):
        n = re.sub(r'\.(list|mrs|txt)$', '', f, flags=re.IGNORECASE)
        n = re.sub(r'_(domain|ip|classical)$', '', n, flags=re.IGNORECASE)
        return n

    sections = {"mrs": [], "surge": [], "mosdns": []}
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

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# 📂 规则集索引\n\n## 🛠 MRS 格式 (Mihomo)\n| 规则名 | 类型 | 文件名 | 相对路径 |\n| :--- | :--- | :--- | :--- |\n")
        for i in sorted(sections["mrs"], key=lambda x: (x['n'], x['t'])):
            f.write(f"| {i['n']} | {i['t']} | {i['f']} | `{i['p']}` |\n")
        f.write("\n## 🛠 Surge 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
        for i in sorted(sections["surge"], key=lambda x: x['n']):
            f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")
        f.write("\n## 🛠 MosDNS 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
        for i in sorted(sections["mosdns"], key=lambda x: x['n']):
            f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")

def main():
    setup_dirs()
    versions = load_versions()
    new_versions = {}

    # 1. 处理 Custom
    if os.path.exists(CUSTOM_DIR):
        for f in os.listdir(CUSTOM_DIR):
            if f.endswith(".txt"):
                name = f.replace(".txt", "")
                with open(os.path.join(CUSTOM_DIR, f), 'r', encoding='utf-8') as file:
                    content = file.read()
                    h = get_hash(content)
                    new_versions[name] = h
                    write_outputs(name, parse_rules(content))

    # 2. 处理 Rules.txt
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"): continue
                name = url.split('/')[-1].replace('.list','').replace('.txt','')
                try:
                    r = requests.get(url, timeout=15)
                    h = get_hash(r.text)
                    new_versions[name] = h
                    if versions.get(name) != h:
                        print(f"🔄 更新: {name}")
                        write_outputs(name, parse_rules(r.text))
                    else:
                        new_versions[name] = h
                except: pass

    save_versions(new_versions)
    generate_readme()

if __name__ == "__main__":
    main()