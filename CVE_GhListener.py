import os
import sqlite3
import requests
import json
import re
import time
from datetime import datetime
from typing import List, Dict, Optional
import utils
import logging
from serverchan_sdk import sc_send

# 从环境变量获取敏感信息
SCKEY = os.getenv("SCKEY")
GH_TOKEN = os.getenv('GH_TOKEN')
DB_PATH = "Github_CVE_Monitor.db"
LOG_FILE = 'Ghflows.log'  # 日志文件前缀
CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

# 日志配置
logger = logging.getLogger("Ghflows")
logger.setLevel(logging.INFO)

# 给翻译函数添加时间延迟
def translate(text,delay_seconds):
    url = 'https://aidemo.youdao.com/trans'
    try:
        data = {"q": text, "from": "auto", "to": "zh-CHS"}
        resp = requests.post(url, data, timeout=15)
        if resp is not None and resp.status_code == 200:
            respJson = resp.json()
            if "translation" in respJson:
                return "\n".join(str(i) for i in respJson["translation"])
            if delay_seconds > 0:
                time.sleep(delay_seconds)
    except Exception:
        logger.warning("Error translating message!")
    return text

def init_db():
    """初始化数据库，创建必要的表"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 创建仓库信息表
    c.execute('''CREATE TABLE IF NOT EXISTS repositories
                 (
                     id INTEGER PRIMARY KEY,
                     name TEXT,
                     description TEXT,
                     url TEXT,
                     pushed_at TEXT,
                     created_at TEXT,
                     updated_at TEXT,
                     cve_ids TEXT
                 )''')

    # 创建检查记录表
    c.execute('''CREATE TABLE IF NOT EXISTS check_records
                 (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     check_time TEXT,
                     total_count INTEGER
                 )''')

    conn.commit()
    conn.close()

def save_repository(repo_info: Dict):
    """保存仓库信息到数据库"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO repositories VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (repo_info['id'], repo_info['name'], repo_info['description'],
                   repo_info['url'], repo_info['pushed_at'], repo_info['created_at'],
                   repo_info['updated_at'], ','.join(repo_info['cve_ids'])))
        conn.commit()
    except sqlite3.IntegrityError:
        logger.info(f"Repository {repo_info['id']} already exists in database")
    finally:
        conn.close()

def repository_exists(repo_id: int) -> bool:
    """检查仓库是否已存在于数据库中"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id FROM repositories WHERE id = ?", (repo_id,))
    result = c.fetchone()
    conn.close()
    return result is not None

def save_check_record(total_count: int):
    """保存检查记录"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO check_records (check_time, total_count) VALUES (?, ?)",
              (datetime.now().isoformat(), total_count))
    conn.commit()
    conn.close()

def get_last_total_count() -> int:
    """获取上次检查的总数"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT total_count FROM check_records ORDER BY id DESC LIMIT 1")
    result = c.fetchone()
    conn.close()
    return result[0] if result else 0

def extract_cve_ids(text: str) -> List[str]:
    """从任意文本中提取 CVE 标识列表（去重，返回大写）"""
    if not text:
        return []
    found = CVE_REGEX.findall(text)
    normalized = sorted({f.upper() for f in found})
    return normalized

def fetch_github_repositories() -> Optional[Dict]:
    """从GitHub API获取CVE相关仓库"""
    year = utils.get_current_year()
    api_url = f"https://api.github.com/search/repositories?q=CVE-{year}&sort=updated&order=desc"
    headers = {"Authorization": f"Bearer {GH_TOKEN}"}

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()

        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch data from GitHub: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return None

def process_new_repositories() -> List[Dict]:
    """处理新仓库并返回新发现的仓库列表"""
    data = fetch_github_repositories()
    if not data or "items" not in data:
        logger.error("No valid data response from GitHub API")
        return []

    current_total = data["total_count"]
    last_total = get_last_total_count()

    # 保存本次检查记录
    save_check_record(current_total)

    if current_total <= last_total:
        logger.info("No new repositories found")
        return []

    new_repositories = []
    for repo in data["items"]:
        repo_id = repo["id"]

        # 跳过已处理的仓库
        if repository_exists(repo_id):
            continue

        # 提取CVE ID
        description = repo.get("description", "") or ""
        cve_ids = extract_cve_ids(description)

        # 准备仓库信息
        repo_info = {
            "id": repo_id,
            "name": repo["name"],
            "description": description,
            "url": repo["html_url"],
            "pushed_at": repo["pushed_at"],
            "created_at": repo["created_at"],
            "updated_at": repo["updated_at"],
            "cve_ids": cve_ids
        }

        # 保存到数据库
        save_repository(repo_info)
        new_repositories.append(repo_info)

        # 只处理前10个新仓库，避免一次处理太多
        if len(new_repositories) >= 10:
            break

    return new_repositories


def send_notification(repo_info: Dict):
    """发送单个仓库的通知"""
    title = f"漏洞仓库: {repo_info['name']}"

    # 翻译描述
    # translated_description = translate(repo_info["description"],20)

    # 构建消息内容
    desp = f"""
## 漏洞仓库详情
**仓库名称**: {repo_info['name']}\n\n
**可能涉及的CVE ID**: {', '.join(repo_info['cve_ids']) if repo_info['cve_ids'] else '未检测到CVE ID'}\n\n
**最后更新时间**: {repo_info['pushed_at']}\n\n
**创建时间**: {repo_info['created_at']}\n\n

## 仓库概述
{repo_info['description']}

## 仓库地址
{repo_info['url']}

## 来源
GitHub
"""
    try:
        response = sc_send(SCKEY, title, desp, {"tags": "GitHub上CVE相关仓库"})
        logger.info(f"Notification sent for repository: {repo_info['name']}, response: {response}")
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")


def main():
    """主函数"""
    # 初始化数据库
    init_db()

    # 处理新仓库
    new_repos = process_new_repositories()

    # 发送通知
    for repo in new_repos:
        send_notification(repo)

if __name__ == "__main__":
    main()