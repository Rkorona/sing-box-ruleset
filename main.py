import csv
import os
import shutil
import logging
import requests
import zipfile
import json
from collections import defaultdict

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}

# 使用脚本所在文件的绝对路径，避免 cron/systemd 执行时路径错误
current_dir = os.path.dirname(os.path.abspath(__file__))
asn_url = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key={}&suffix=zip"
asn_v4 = defaultdict(list)
asn_v6 = defaultdict(list)

# 定义要下载的额外 Surge 规则配置
extra_surge_conf = {}


class RuleSet(object):
    def __init__(self, domain, domain_keyword, domain_suffix, ip_cidr, process_name):
        self.version = 2
        self.rules = list()

        # 聚合域名和IP类规则
        domain_rules = {}
        if domain:
            domain_rules["domain"] = sorted(list(set(domain)))
        if domain_keyword:
            domain_rules["domain_keyword"] = sorted(list(set(domain_keyword)))
        if domain_suffix:
            domain_rules["domain_suffix"] = sorted(list(set(domain_suffix)))
        if ip_cidr:
            domain_rules["ip_cidr"] = sorted(list(set(ip_cidr)))

        if domain_rules:
            self.rules.append(domain_rules)

        # 聚合进程类规则
        if process_name:
            self.rules.append({"process_name": sorted(list(set(process_name)))})


def init():
    # 删除已有文件夹
    dir_path = os.path.join(current_dir, "rule")
    if os.path.exists(dir_path) and os.path.isdir(dir_path):
        logging.warning(f"{dir_path} exists, delete!")
        shutil.rmtree(dir_path)
    os.makedirs(dir_path)

    # 获取 asn 文件
    maxmind_key = os.environ.get("MAXMIND_KEY", "").strip()
    if not maxmind_key:
        logging.critical("MAXMIND_KEY not set!")
        exit(1)

    logging.info("downloading asn file...")
    zip_path = os.path.join(current_dir, "asn.zip")

    try:
        response = requests.get(
            asn_url.format(maxmind_key), headers=headers, timeout=60
        )
        response.raise_for_status()
        with open(zip_path, "wb") as file:
            file.write(response.content)
        logging.info("downloading asn file complete")
    except requests.RequestException as e:
        logging.critical(f"downloading asn file error: {e}")
        exit(1)

    # 解压 asn 文件
    asn_folder_path = os.path.join(current_dir, "asn")
    os.makedirs(asn_folder_path, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for file_info in zip_ref.infolist():
            # 获取文件名（忽略第一层目录）
            parts = file_info.filename.split("/")
            if len(parts) > 1 and parts[-1]:  # 确保不是文件夹且在子目录中
                file_name = parts[-1]
                target_path = os.path.join(asn_folder_path, file_name)
                with open(target_path, "wb") as f_out:
                    f_out.write(zip_ref.read(file_info))

    logging.info(f"unzip asn files to {asn_folder_path}")

    # 汇总 asn 信息
    asn_v4_file = os.path.join(asn_folder_path, "GeoLite2-ASN-Blocks-IPv4.csv")
    asn_v6_file = os.path.join(asn_folder_path, "GeoLite2-ASN-Blocks-IPv6.csv")

    def load_asn(file_path, target_dict):
        if not os.path.exists(file_path):
            logging.warning(f"ASN file not found: {file_path}")
            return
        with open(file_path, mode="r", encoding="utf-8") as f:
            csv_reader = csv.reader(f, delimiter=",")
            next(csv_reader)  # Skip header
            for row in csv_reader:
                if row and len(row) >= 2:
                    # row[1] is ASN, row[0] is CIDR
                    target_dict[int(row[1])].append(row[0])

    load_asn(asn_v4_file, asn_v4)
    # [Fix] 修正这里原本使用了 asn_v4 的错误
    load_asn(asn_v6_file, asn_v6)

    logging.info("aggregating asn info finishes")


source_repo_url = (
    "https://github.com/blackmatrix7/ios_rule_script/archive/refs/heads/master.zip"
)


def download_source_repo():
    logging.info("downloading rule source file...")
    source_zip = os.path.join(current_dir, "ios_rule_script.zip")
    try:
        response = requests.get(source_repo_url, headers=headers, timeout=60)
        response.raise_for_status()
        with open(source_zip, "wb") as file:
            file.write(response.content)
        logging.info("downloading rule source complete")
    except requests.RequestException as e:
        logging.critical(f"downloading rule source error: {e}")
        exit(1)

    source_folder = os.path.join(current_dir, "ios_rule_script")
    os.makedirs(source_folder, exist_ok=True)
    with zipfile.ZipFile(source_zip, "r") as zip_ref:
        zip_ref.extractall(source_folder)
    logging.info(f"unzip rule source to {source_folder}")


subs = ["Assassin'sCreed", "Cloud"]


def save_rule_to_file(
    name, target_dir, domain, domain_keyword, domain_suffix, ip_cidr, process_name
):
    """通用保存函数，消除重复代码"""
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    target_file = os.path.join(target_dir, f"{name}.json")
    rule_content = RuleSet(domain, domain_keyword, domain_suffix, ip_cidr, process_name)

    with open(target_file, "w", encoding="utf-8") as json_file:
        json.dump(
            rule_content,
            json_file,
            default=lambda obj: obj.__dict__,
            sort_keys=True,  # 保持输出有序
            indent=2,
        )

    readme_file = os.path.join(target_dir, "README.md")
    # 使用 f-string 的多行写法更清晰
    readme_content = (
        f"# {name}\n\n"
        f"#### 规则链接\n\n"
        f"**Github**\n"
        f"https://raw.githubusercontent.com/rkorona/sing-box-ruleset/main/rule/{name}/{
            name
        }.srs\n\n"
        f"**CDN**\n"
        f"https://cdn.jsdelivr.net/gh/rkorona/sing-box-ruleset@main/rule/{name}/{
            name
        }.srs"
    )
    with open(readme_file, "w", encoding="utf-8") as readme:
        readme.write(readme_content)


def parse_and_convert(entry, source_file, target_dir):
    """解析文件并转换"""
    domain = list()
    domain_keyword = list()
    domain_suffix = list()
    ip_cidr = list()
    process_name = list()

    # 处理 YAML (Clash)
    if source_file.endswith(".yaml"):
        found_payload = False
        with open(source_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if "payload:" in line:
                    found_payload = True
                    continue
                if not found_payload or not line.startswith("-"):
                    continue

                # 更稳健的解析: 去掉开头的 "- " 或 "-"
                content = line[1:].strip().strip("'").strip('"')
                # 兼容行尾可能有注释的情况，但这里简单按逗号分割
                splits = content.split(",")
                if len(splits) < 2:
                    continue

                rule_type = splits[0].strip()
                rule_content = splits[1].strip()

                # 统一添加到对应的列表
                append_rule(
                    rule_type,
                    rule_content,
                    domain,
                    domain_suffix,
                    domain_keyword,
                    ip_cidr,
                    process_name,
                )

    # 处理 Conf (Surge/Generic)
    else:
        with open(source_file, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                splits = line.split(",")
                if len(splits) < 2:
                    continue

                rule_type = splits[0].strip()
                rule_content = splits[1].strip()
                append_rule(
                    rule_type,
                    rule_content,
                    domain,
                    domain_suffix,
                    domain_keyword,
                    ip_cidr,
                    process_name,
                )

    save_rule_to_file(
        entry, target_dir, domain, domain_keyword, domain_suffix, ip_cidr, process_name
    )


def append_rule(
    rule_type,
    rule_content,
    domain,
    domain_suffix,
    domain_keyword,
    ip_cidr,
    process_name,
):
    if rule_type == "DOMAIN":
        domain.append(rule_content)
    elif rule_type == "DOMAIN-SUFFIX":
        domain_suffix.append(rule_content)
    elif rule_type == "DOMAIN-KEYWORD":
        domain_keyword.append(rule_content)
    elif rule_type in ["IP-CIDR", "IP-CIDR6"]:
        ip_cidr.append(rule_content)
    elif rule_type == "IP-ASN":
        try:
            asn_num = int(rule_content)
            ip_cidr.extend(asn_v4[asn_num])
            ip_cidr.extend(asn_v6[asn_num])
        except ValueError:
            logging.warning(f"Invalid ASN: {rule_content}")
    elif rule_type == "PROCESS-NAME":
        process_name.append(rule_content)


def translate_rule():
    source_folder = os.path.join(
        current_dir, "ios_rule_script/ios_rule_script-master/rule/Clash"
    )
    target_folder = os.path.join(current_dir, "rule")

    if not os.path.exists(source_folder):
        logging.error(f"Source folder not found: {source_folder}")
        return

    for entry in os.listdir(source_folder):
        if entry == "CGB":
            continue

        entry_path = os.path.join(source_folder, entry)
        if not os.path.isdir(entry_path):
            continue

        if entry in subs:
            for subEntry in os.listdir(entry_path):
                sub_source_dir = os.path.join(entry_path, subEntry)
                sub_target_dir = os.path.join(target_folder, subEntry)

                # 寻找源文件
                source_file = os.path.join(sub_source_dir, f"{subEntry}.yaml")
                if os.path.exists(
                    os.path.join(sub_source_dir, f"{subEntry}_Classical.yaml")
                ):
                    source_file = os.path.join(
                        sub_source_dir, f"{subEntry}_Classical.yaml"
                    )

                if os.path.exists(source_file):
                    parse_and_convert(subEntry, source_file, sub_target_dir)
        else:
            target_dir = os.path.join(target_folder, entry)
            source_file = os.path.join(entry_path, f"{entry}.yaml")
            if os.path.exists(os.path.join(entry_path, f"{entry}_Classical.yaml")):
                source_file = os.path.join(entry_path, f"{entry}_Classical.yaml")

            if os.path.exists(source_file):
                parse_and_convert(entry, source_file, target_dir)

    logging.info(f"finish translating clash rules")


def translate_extra():
    if not extra_surge_conf:
        return

    logging.info("translating extra surge rule...")
    target_folder = os.path.join(current_dir, "rule")

    for k, v in extra_surge_conf.items():
        source_file = os.path.join(current_dir, f"{k}.conf")
        try:
            response = requests.get(v, headers=headers, timeout=30)
            response.raise_for_status()
            with open(source_file, "wb") as file:
                file.write(response.content)
            logging.info(f"downloading {k}.conf complete")

            target_dir = os.path.join(target_folder, k)
            parse_and_convert(k, source_file, target_dir)

        except requests.RequestException as e:
            logging.critical(f"downloading {k}.conf error: {e}")
            exit(1)


def generate_ruleset_stats():
    rule_dir = os.path.join(current_dir, "rule")
    if not os.path.exists(rule_dir):
        logging.warning("rule directory not found, skip stats generation")
        return

    # 每个子文件夹 = 一个规则集
    rulesets = [
        name
        for name in os.listdir(rule_dir)
        if os.path.isdir(os.path.join(rule_dir, name))
    ]
    count = len(rulesets)

    stats_md = f"- 当前共生成 **{count}** 个规则集\n"

    readme_path = os.path.join(current_dir, "README.md")
    if not os.path.exists(readme_path):
        logging.warning("README.md not found, skip stats update")
        return

    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()

    start = "<!-- RULESET_STATS_START -->"
    end = "<!-- RULESET_STATS_END -->"

    if start not in content or end not in content:
        logging.warning("README stats markers not found")
        return

    new_content = (
        content.split(start)[0] + start + "\n" + stats_md + end + content.split(end)[1]
    )

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    logging.info(f"update ruleset stats: {count} rulesets")


def post_clean():
    # 使用 ignore_errors 防止文件占用导致的报错
    shutil.rmtree(os.path.join(current_dir, "asn"), ignore_errors=True)
    shutil.rmtree(os.path.join(current_dir, "ios_rule_script"), ignore_errors=True)

    try:
        os.remove(os.path.join(current_dir, "asn.zip"))
    except FileNotFoundError:
        pass

    try:
        os.remove(os.path.join(current_dir, "ios_rule_script.zip"))
    except FileNotFoundError:
        pass

    for key in extra_surge_conf:
        try:
            os.remove(os.path.join(current_dir, f"{key}.conf"))
        except FileNotFoundError:
            pass


def main():
    init()
    download_source_repo()
    translate_rule()
    translate_extra()
    generate_ruleset_stats()
    post_clean()


if __name__ == "__main__":
    main()

