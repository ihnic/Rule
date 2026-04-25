import requests
import re
import os
import subprocess
import hashlib
import json

# --- 配置 ---
RULES_FILE = "rules.txt"
CUSTOM_DIR = "custom"
VERSION_FILE = "versions.json"  # 用于存储 Hash，实现局部更新
OUTPUT_DIRS = {
    "mihomo": ["mihomo/domain", "mihomo/ip", "mihomo/classical"],
    "surge": ["surge"],
    "mosdns": ["mosdns"]
}
MIHOMO_BIN = "./mihomo-core"

def get_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_versions():
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, 'r') as f: return json.load(f)
    return {}

def save_versions(versions):
    with open(VERSION_FILE, 'w') as f: json.dump(versions, f, indent=4)

def setup_dirs():
    for platforms in OUTPUT_DIRS.values():
        for d in platforms: os.makedirs(d, exist_ok=True)

def parse_rules(content):
    """核心转换逻辑：将输入解析为标准化的三个分类"""
    result = {"domain": [], "ip": [], "classical": []}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        clean_line = re.sub(r'^-\s*', '', line)

        # 转换为三方通用的标准化格式
        if 'DOMAIN-SUFFIX' in clean_line or clean_line.startswith('+.'):
            domain = clean_line.split(',')[-2] if ',' in clean_line else clean_line.replace('+.','')
            result["domain"].append(domain)
        elif 'DOMAIN,' in clean_line:
            result["domain"].append(f"FULL:{clean_line.split(',')[1]}") # 标记为全匹配
        elif 'IP-CIDR' in clean_line:
            result["ip"].append(clean_line.split(',')[1])
        elif 'DOMAIN-KEYWORD' in clean_line:
            result["classical"].append(clean_line)
        else:
            result["classical"].append(clean_line)
    return result

def write_outputs(name, data):
    """分发到不同平台的文件夹"""
    # 1. Surge 格式 (.list)
    surge_file = f"surge/{name}.list"
    with open(surge_file, 'w') as f:
        for d in data["domain"]:
            if d.startswith("FULL:"): f.write(f"DOMAIN,{d.replace('FULL:','')}\n")
            else: f.write(f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip}\n")
        for cls in data["classical"]: f.write(f"{cls}\n")

    # 2. MosDNS 格式 (.txt)
    mosdns_file = f"mosdns/{name}.txt"
    with open(mosdns_file, 'w') as f:
        for d in data["domain"]:
            if d.startswith("FULL:"): f.write(f"full:{d.replace('FULL:','')}\n")
            else: f.write(f"domain:{d}\n")
        for cls in data["classical"]:
            if "DOMAIN-KEYWORD" in cls: f.write(f"keyword:{cls.split(',')[1]}\n")

    # 3. Mihomo 文本格式 (用于编译)
    for cat in ["domain", "ip", "classical"]:
        ext = "list"
        items = data[cat]
        if not items: continue
        path = f"mihomo/{cat}/{name}.{ext}"
        with open(path, 'w') as f:
            for item in items:
                if cat == "domain":
                    f.write(f"+.{item.replace('FULL:','')}\n" if "FULL:" not in item else f"{item.replace('FULL:','')}\n")
                else: f.write(f"{item}\n")
        
        # 编译 MRS (仅 domain 和 ip)
        if cat in ["domain", "ip"]:
            mrs_path = path.replace(".list", ".mrs")
            behavior = "ipcidr" if cat == "ip" else "domain"
            subprocess.run([MIHOMO_BIN, "convert-ruleset", behavior, "text", path, mrs_path], capture_output=True)

def main():
    setup_dirs()
    versions = load_versions()
    new_versions = {}
    current_names = []

    # 处理 custom 文件夹
    for f in os.listdir(CUSTOM_DIR):
        if not f.endswith(".txt"): continue
        name = f.replace(".txt", "")
        current_names.append(name)
        with open(os.path.join(CUSTOM_DIR, f), 'r') as file:
            content = file.read()
            h = get_hash(content)
            new_versions[name] = h
            if versions.get(name) != h:
                print(f"🔄 更新自定义规则: {name}")
                write_outputs(name, parse_rules(content))

    # 处理 rules.txt
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            for line in f:
                if not line.strip() or line.startswith("#"): continue
                url = line.strip()
                name = url.split('/')[-1].split('.')[0]
                current_names.append(name)
                try:
                    res = requests.get(url, timeout=15)
                    h = get_hash(res.text)
                    new_versions[name] = h
                    if versions.get(name) != h:
                        print(f"📡 更新远程规则: {name}")
                        write_outputs(name, parse_rules(res.text))
                except: print(f"❌ 下载失败: {url}")

    # 清理已删除的规则
    # (逻辑：遍历目录，如果文件名不在 current_names 里，则 os.remove)
    
    save_versions(new_versions)
    # 最后调用 README 生成函数 (省略具体生成逻辑，可复用之前的)

if __name__ == "__main__":
    main()