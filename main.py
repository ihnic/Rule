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

# 读取 Action 传过来的强制更新参数
FORCE_REWRITE = os.getenv("FORCE_UPDATE") == "true"

def get_raw_url(url):
    """自动将 GitHub 网页链接转换为 Raw 原始数据链接"""
    if "github.com" in url and "/blob/" in url:
        return url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    return url

def get_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_versions():
    if FORCE_REWRITE: return {} # 强制更新模式下不读取旧缓存
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_versions(versions):
    with open(VERSION_FILE, 'w', encoding='utf-8') as f:
        json.dump(versions, f, indent=4, ensure_ascii=False)

def setup_dirs():
    # 彻底解决文件/文件夹同名冲突
    if os.path.isfile("mihomo"):
        try: os.remove("mihomo")
        except: pass

    # 强制清理：如果开启强制重写，直接物理删除输出目录
    if FORCE_REWRITE:
        print("🗑️ [强制模式] 正在物理清空旧规则目录，确保无残留文件...")
        for d in ["mihomo", "surge", "mosdns"]:
            if os.path.exists(d):
                shutil.rmtree(d)

    # 重新创建目录
    for d in DIRS:
        os.makedirs(d, exist_ok=True)

def parse_rules(content):
    """原子化解析引擎"""
    if not content or "<!DOCTYPE html>" in content or "<html" in content:
        print("⚠️ 忽略非规则内容 (可能是 HTML 网页)")
        return None
        
    res = {"domain": [], "full": [], "ip": [], "classical": []}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        
        raw_line = re.sub(r'^-\s*', '', line)
        parts = [p.strip() for p in raw_line.split(',')]
        tag = parts[0].upper()
        
        try:
            if tag == 'DOMAIN-SUFFIX':
                res["domain"].append(parts[1])
            elif tag == 'DOMAIN':
                res["full"].append(parts[1])
            elif tag in ['IP-CIDR', 'IP-CIDR6']:
                res["ip"].append(parts[1])
            elif tag in ['PROCESS-NAME', 'DOMAIN-KEYWORD']:
                res["classical"].append(f"{tag},{parts[1]}")
            elif raw_line.startswith('+.'):
                res["domain"].append(raw_line.replace('+.',''))
            elif len(parts) == 1 and '.' in raw_line:
                res["full"].append(raw_line)
        except IndexError:
            continue
    return res

def write_outputs(name, data):
    """多平台同步输出"""
    if not data: return

    # 1. Surge
    with open(f"surge/{name}.list", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"DOMAIN,{d}\n")
        for d in data["domain"]: f.write(f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip},no-resolve\n")
        for cls in data["classical"]: f.write(f"{cls}\n")

    # 2. MosDNS
    with open(f"mosdns/{name}.txt", 'w', encoding='utf-8') as f:
        for d in data["full"]: f.write(f"full:{d}\n")
        for d in data["domain"]: f.write(f"domain:{d}\n")
        for cls in data["classical"]:
            if cls.startswith("DOMAIN-KEYWORD"):
                f.write(f"keyword:{cls.split(',')[1]}\n")

    # 3. Mihomo
    if data["domain"] or data["full"]:
        p = f"mihomo/domain/{name}.list"
        with open(p, 'w', encoding='utf-8') as f:
            for d in data["full"]: f.write(f"{d}\n")
            for d in data["domain"]: f.write(f"+.{d}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "domain", "text", p, p.replace(".list", ".mrs")], capture_output=True)

    if data["ip"]:
        p = f"mihomo/ip/{name}.list"
        with open(p, 'w', encoding='utf-8') as f:
            for ip in data["ip"]: f.write(f"{ip}\n")
        subprocess.run([MIHOMO_BIN, "convert-ruleset", "ipcidr", "text", p, p.replace(".list", ".mrs")], capture_output=True)

    if data["classical"]:
        with open(f"mihomo/classical/{name}.list", 'w', encoding='utf-8') as f:
            f.write("\n".join(data["classical"]))

def generate_readme():
    """生成包含所有平台的索引 README"""
    readme_path = "README.md"
    def clean_name(f):
        n = re.sub(r'\.(list|mrs|txt)$', '', f, flags=re.IGNORECASE)
        n = re.sub(r'_(domain|ip|classical)$', '', n, flags=re.IGNORECASE)
        return n

    res = {"mrs": [], "surge": [], "mosdns": []}
    for cat in ['domain', 'ip']:
        p = f"mihomo/{cat}"
        if os.path.exists(p):
            for f in sorted(os.listdir(p)):
                if f.endswith(".mrs"):
                    res["mrs"].append({"n": clean_name(f), "t": cat, "f": f, "p": f"./mihomo/{cat}/{f}"})
    if os.path.exists("surge"):
        for f in sorted(os.listdir("surge")):
            if f.endswith(".list"):
                res["surge"].append({"n": clean_name(f), "f": f, "p": f"./surge/{f}"})
    if os.path.exists("mosdns"):
        for f in sorted(os.listdir("mosdns")):
            if f.endswith(".txt"):
                res["mosdns"].append({"n": clean_name(f), "f": f, "p": f"./mosdns/{f}"})

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# 📂 规则集索引\n\n> 自动化同步工厂，北京时间凌晨 03:00 更新。\n\n")
        f.write("## 🛠 MRS 格式 (Mihomo)\n| 规则名 | 类型 | 文件名 | 相对路径 |\n| :--- | :--- | :--- | :--- |\n")
        for i in res["mrs"]: f.write(f"| {i['n']} | {i['t']} | {i['f']} | `{i['p']}` |\n")
        f.write("\n## 🛠 Surge 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
        for i in res["surge"]: f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")
        f.write("\n## 🛠 MosDNS 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
        for i in res["mosdns"]: f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")
        f.write(f"\n\n> 最后更新: {subprocess.getoutput('date')}")

def main():
    setup_dirs()
    versions = load_versions()
    new_versions = {}

    # 1. 处理 Custom
    if os.path.exists(CUSTOM_DIR):
        for f in os.listdir(CUSTOM_DIR):
            if f.endswith(".txt"):
                # 将文件名中的 @ 转换为 -
                name = f.replace(".txt", "").replace("@", "-")
                with open(os.path.join(CUSTOM_DIR, f), 'r', encoding='utf-8') as file:
                    content = file.read()
                    h = get_hash(content)
                    new_versions[name] = h
                    if versions.get(name) != h or FORCE_REWRITE:
                        write_outputs(name, parse_rules(content))

    # 2. 处理 Rules.txt
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"): continue
                
                raw_url = get_raw_url(url)
                # 精准提取名称并转换 @ 为 -
                name = url.split('/')[-1].replace('.list','').replace('.txt','').replace('@', '-')
                
                try:
                    r = requests.get(raw_url, timeout=15)
                    h = get_hash(r.text)
                    new_versions[name] = h
                    if versions.get(name) != h or FORCE_REWRITE:
                        print(f"🔄 正在转换: {name}")
                        data = parse_rules(r.text)
                        if data: write_outputs(name, data)
                except:
                    print(f"❌ 无法下载: {name}")
                    if name in versions: new_versions[name] = versions[name]

    save_versions(new_versions)
    generate_readme()

if __name__ == "__main__":
    main()
