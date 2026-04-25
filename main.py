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
MIHOMO_BIN = "./mihomo-core"  # 确保仓库里 Linux 内核叫这个名字
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

def save_versions(versions):
    """保存当前的 Hash 记录到文件"""
    with open(VERSION_FILE, 'w', encoding='utf-8') as f:
        json.dump(versions, f, indent=4, ensure_ascii=False)

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
            # 兼容 Surge 格式和 MosDNS 格式
            k = clean.split(',')[1] if ',' in clean else clean.replace('keyword:','')
            res["classical"].append(f"DOMAIN-KEYWORD,{k}")
        else:
            res["classical"].append(clean)
    return res

def write_outputs(name, data):
    """一源三发：将解析后的数据分发到不同平台"""
    # 1. Surge 导出 (.list)
    with open(f"surge/{name}.list", 'w', encoding='utf-8') as f:
        for d in data["domain"]:
            if "FULL:" in d:
                f.write(f"DOMAIN,{d.replace('FULL:','')}\n")
            else:
                f.write(f"DOMAIN-SUFFIX,{d}\n")
        for ip in data["ip"]: f.write(f"IP-CIDR,{ip}\n")
        for cls in data["classical"]: f.write(f"{cls}\n")

    # 2. MosDNS 导出 (.txt)
    with open(f"mosdns/{name}.txt", 'w', encoding='utf-8') as f:
        for d in data["domain"]:
            if "FULL:" in d:
                f.write(f"full:{d.replace('FULL:','')}\n")
            else:
                f.write(f"domain:{d}\n")
        for cls in data["classical"]:
            if "DOMAIN-KEYWORD" in cls:
                f.write(f"keyword:{cls.split(',')[1]}\n")

    # 3. Mihomo 导出与编译
    for cat in ["domain", "ip", "classical"]:
        items = data[cat]
        if not items: continue
        txt_path = f"mihomo/{cat}/{name}.list"
        with open(txt_path, 'w', encoding='utf-8') as f:
            for item in items:
                if cat == "domain":
                    if "FULL:" in item:
                        f.write(f"{item.replace('FULL:','')}\n")
                    else:
                        f.write(f"+.{item}\n")
                else: f.write(f"{item}\n")
        
        # 编译二进制 MRS (仅 domain 和 ip)
        if cat in ["domain", "ip"]:
            mrs_path = txt_path.replace(".list", ".mrs")
            bh = "ipcidr" if cat == "ip" else "domain"
            # 注意这里调用的是 ./mihomo-core
            subprocess.run([MIHOMO_BIN, "convert-ruleset", bh, "text", txt_path, mrs_path], capture_output=True)

def generate_readme():
    """生成全平台合并索引 README"""
    readme_path = "README.md"
    
    def clean_name(f):
        # 依次切掉可能出现的多种后缀和类型标识
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
        f.write("# 📂 规则集索引\n\n> 自动化同步流水线，北京时间每天 03:00 更新。\n\n")

        # 1. MRS 表格
        if sections["mrs"]:
            f.write("## 🛠 MRS 格式 (Mihomo)\n| 规则名 | 类型 | 文件名 | 相对路径 |\n| :--- | :--- | :--- | :--- |\n")
            sorted_mrs = sorted(sections["mrs"], key=lambda x: (x['n'], x['t']))
            for i in sorted_mrs:
                f.write(f"| {i['n']} | {i['t']} | {i['f']} | `{i['p']}` |\n")

        # 2. Surge 表格
        if sections["surge"]:
            f.write("\n## 🛠 Surge 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
            for i in sorted(sections["surge"], key=lambda x: x['n']):
                f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")

        # 3. MosDNS 表格
        if sections["mosdns"]:
            f.write("\n## 🛠 MosDNS 格式\n| 规则名 | 文件名 | 相对路径 |\n| :--- | :--- | :--- |\n")
            for i in sorted(sections["mosdns"], key=lambda x: x['n']):
                f.write(f"| {i['n']} | {i['f']} | `{i['p']}` |\n")

        f.write(f"\n\n> 最后更新: {subprocess.getoutput('date')}")

def main():
    setup_dirs()
    versions = load_versions()
    new_versions = {}
    
    # 1. 处理 Custom 文件夹
    if os.path.exists(CUSTOM_DIR):
        for f in os.listdir(CUSTOM_DIR):
            if f.endswith(".txt"):
                name = f.replace(".txt", "")
                with open(os.path.join(CUSTOM_DIR, f), 'r', encoding='utf-8') as file:
                    content = file.read()
                    h = get_hash(content)
                    new_versions[name] = h
                    # 只有 Hash 不同或文件不存在时才写入
                    write_outputs(name, parse_rules(content))

    # 2. 处理 Rules.txt
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if not url or url.startswith("#"): continue
                # 获取文件名作为规则名
                name = url.split('/')[-1].replace('.list','').replace('.txt','')
                try:
                    r = requests.get(url, timeout=15)
                    r.raise_for_status()
                    h = get_hash(r.text)
                    new_versions[name] = h
                    # 只有远程更新了才重新处理
                    if versions.get(name) != h:
                        print(f"📡 更新规则: {name}")
                        write_outputs(name, parse_rules(r.text))
                    else:
                        # 如果没变，也要继承旧的 Hash 记录，否则下次还会下载
                        new_versions[name] = h
                except Exception as e:
                    print(f"❌ 抓取失败 {url}: {e}")
                    # 如果下载失败，保留旧的 hash 以免记录丢失
                    if name in versions: new_versions[name] = versions[name]

    # 保存新的版本记录
    save_versions(new_versions)
    # 生成索引文档
    generate_readme()

if __name__ == "__main__":
    main()