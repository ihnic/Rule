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
    if [ -f "mihomo" ]; then rm -f mihomo; fi # 防止同名文件冲突
    for d in DIRS:
        os.makedirs(d, exist_ok=True)

def parse_rules(content):
    """
    精准解析逻辑：
    res['domain'] 存纯域名 (对应 DOMAIN-SUFFIX)
    res['full'] 存纯域名 (对应 DOMAIN)
    res['ip'] 存 IP 段
    res['classical'] 存 进程名/关键字等
    """
    res = {"domain": [], "full": [], "ip": [], "classical": []}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        
        # 统一去掉横杠前缀
        parts = re.sub(r'^-\s*', '', line).split(',')
        tag = parts[0].strip().upper()
        
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
        # 6. 处理原本就是 Mihomo 格式的简写
        elif line.startswith('+.'):
            res["domain"].append(line.replace('+.','').strip())
        else:
            # 无法识别的暂时归入 classical
            res["classical"].append(line)
    return res

def write_outputs(name, data):
    # --- 1. Surge 导出 ---
    with open(f"surge/{name}.list", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"DOMAIN,{d}\n")
        for d in data["domain"]: f.write(f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip},no-resolve\n")
        for cls in data["classical"]: f.write(f"{cls}\n")

    # --- 2. MosDNS 导出 ---
    with open(f"mosdns/{name}.txt", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"full:{d}\n")
        for d in data["domain"]: f.write(f"domain:{d}\n")
        # MosDNS 通常不放 IP 和进程名

    # --- 3. Mihomo 导出 ---
    # Domain 文件夹 (MRS)
    if data["domain"] or data["full"]:
        txt_path = f"mihomo/domain/{name}.list"
        with open(txt_path, 'w', encoding='utf-8') as f:
            for d in data["full"]: f.write(f"{d}\n")
            for d in data["domain"]: f.write(f"+.{d}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "domain", "text", txt_path, txt_path.replace(".list", ".mrs")])

    # IP 文件夹 (MRS)
    if data["ip"]:
        txt_path = f"mihomo/ip/{name}.list"
        with open(txt_path, 'w', encoding='utf-8') as f:
            for ip in data["ip"]: f.write(f"{ip}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "ipcidr", "text", txt_path, txt_path.replace(".list", ".mrs")])

    # Classical 文件夹 (Text)
    if data["classical"]:
        with open(f"mihomo/classical/{name}.list", 'w', encoding='utf-8') as f:
            for cls in data["classical"]: f.write(f"{cls}\n")

def generate_readme():
    readme_path = "README.md"
    def clean_name(f):
        n = re.sub(r'\.(list|mrs|txt)$', '', f, flags=re.IGNORECASE)
        n = re.sub(r'_(domain|ip|classical)$', '', n, flags=re.IGNORECASE)
        return n

    sections = {"mrs": [], "surge": [], "mosdns": []}
    # 扫描 MRS
    for cat in ['domain', 'ip']:
        p = f"mihomo/{cat}"
        if os.path.exists(p):
            for f in os.listdir(p):
                if f.endswith(".mrs"):
                    sections["mrs"].append({"n": clean_name(f), "t": cat, "f": f, "p": f"./mihomo/{cat}/{f}"})
    # 扫描 Surge
    if os.path.exists("surge"):
        for f in os.listdir("surge"):
            sections["surge"].append({"n": clean_name(f), "f": f, "p": f"./surge/{f}"})
    # 扫描 MosDNS
    if os.path.exists("mosdns"):
        for f in os.listdir("mosdns"):
            sections["mosdns"].append({"n": clean_name(f), "f": f, "p": f"./mosdns/{f}"})

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# 📂 规则集索引\n\n## 🛠 MRS 格式\n| 规则名 | 类型 | 文件名 | 相对路径 |\n| :--- | :--- | :--- | :--- |\n")
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
            for url in f:
                url = url.strip()
                if not url or url.startswith("#"): continue
                name = url.split('/')[-1].replace('.list','').replace('.txt','')
                try:
                    r = requests.get(url, timeout=15)
                    h = get_hash(r.text)
                    new_versions[name] = h
                    if versions.get(name) != h:
                        print(f"🔄 更新: {name}")
                        write_outputs(name, parse_rules(r.text))
                except: print(f"❌ 失败: {url}")

    save_versions(new_versions)
    generate_readme()

if __name__ == "__main__":
    main()