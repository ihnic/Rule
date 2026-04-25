import requests
import re
import os
import subprocess
import hashlib
import json

# --- 配置 ---
RULES_FILE = "rules.txt"
CUSTOM_DIR = "custom"
VERSION_FILE = "versions.json"
MIHOMO_BIN = "./mihomo-core" # 必须确保与仓库文件名一致
# 定义输出目录
DIRS = {
    "mihomo": ["mihomo/domain", "mihomo/ip", "mihomo/classical"],
    "surge": ["surge"],
    "mosdns": ["mosdns"]
}

def get_hash(text):
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def load_versions():
    if os.path.exists(VERSION_FILE):
        try:
            with open(VERSION_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def setup_dirs():
    for platforms in DIRS.values():
        for d in platforms: os.makedirs(d, exist_ok=True)

def parse_rules(content):
    """根据 Nic 哥提供的协议逻辑进行精准转换"""
    res = {"domain": [], "ip": [], "classical": []}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', 'payload:')): continue
        clean = re.sub(r'^-\s*', '', line)

        if 'DOMAIN-SUFFIX' in clean or clean.startswith('+.'):
            # 提取域名，去掉前缀
            d = clean.split(',')[-2] if ',' in clean else clean.replace('+.','')
            res["domain"].append(d)
        elif 'DOMAIN,' in clean:
            res["domain"].append(f"FULL:{clean.split(',')[1]}")
        elif 'IP-CIDR' in clean:
            res["ip"].append(clean.split(',')[1])
        elif 'IP-ASN' in clean:
            res["classical"].append(clean) # ASN 放入 classical
        else:
            res["classical"].append(clean)
    return res

def write_outputs(name, data):
    # 1. Surge 导出
    with open(f"surge/{name}.list", 'w', encoding='utf-8') as f:
        for d in data["domain"]:
            f.write(f"DOMAIN,{d.replace('FULL:','')}\n" if "FULL:" in d else f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip}\n")
        for cls in data["classical"]: f.write(f"{cls}\n")

    # 2. MosDNS 导出
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
        
        # 编译 MRS
        if cat in ["domain", "ip"]:
            mrs_path = txt_path.replace(".list", ".mrs")
            bh = "ipcidr" if cat == "ip" else "domain"
            subprocess.run([MIHOMO_BIN, "convert-ruleset", bh, "text", txt_path, mrs_path])

def generate_readme():
    """生成 Nic 哥要求的规则名优先表格"""
    readme_path = "README.md"
    def clean_name(f): return re.sub(r'_(domain|ip|classical)\.(list|mrs|txt)$', '', f, flags=re.IGNORECASE)
    
    # 收集数据
    mrs_list = []
    for cat in ['domain', 'ip']:
        p = f"mihomo/{cat}"
        if os.path.exists(p):
            for f in os.listdir(p):
                if f.endswith(".mrs"):
                    mrs_list.append({"n": clean_name(f), "t": cat, "f": f, "p": f"./mihomo/{cat}/{f}"})

    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write("# 📂 规则集索引\n\n## 🛠 MRS 格式\n| 规则名 | 类型 | 文件名 | 相对路径 |\n| :--- | :--- | :--- | :--- |\n")
        for i in sorted(mrs_list, key=lambda x: (x['n'], x['t'])):
            f.write(f"| {i['n']} | {i['t']} | {i['f']} | `{i['p']}` |\n")
        
        # 可在此继续添加 Surge 和 MosDNS 的表格，逻辑同上
        f.write(f"\n\n> 最后更新时间: {subprocess.getoutput('date')}")

def main():
    setup_dirs()
    versions = load_versions()
    new_versions = {}
    
    # 逻辑：处理 custom 和 rules.txt (略，同之前逻辑)
    # ...
    
    generate_readme() # 核心：无论是否更新，最后都重新生成 README

if __name__ == "__main__":
    main()