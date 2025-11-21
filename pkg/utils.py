from datetime import datetime
import requests
import logging
import time


def get_current_year():
    """获取当前年份"""
    return datetime.now().year

def get_cve_overview(cve_id: str) -> str:
    """通过CVE API获取CVE的概述信息"""
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        response = requests.get(url)
        response.raise_for_status()

        data = response.json()
        if 'summary' in data:
            return data['summary']
        else:
            return "No overview available for this CVE."
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch CVE overview for {cve_id}: {str(e)}")
        return "Error fetching CVE overview."

def translate(text, delay_seconds):
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
        logging.warning("Error translating message!")
    return text