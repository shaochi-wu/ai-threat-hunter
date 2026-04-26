import os
import re
import sqlite3
import httpx
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# ==========================================
# 1. 系統設定與常數 (Configuration & Constants)
# ==========================================
mcp = FastMCP("ThreatIntelServer")
DB_FILE = "threat_intel.db"

# 高風險特徵字典 (用於動態加權)
HIGH_RISK_COUNTRIES = ["Russia", "North Korea", "Iran", "China"]
HIGH_RISK_ISPS = ["DigitalOcean", "Linode", "OVH", "Choopa", "ColoCrossing"]
TRUSTED_ORGS = ["Google LLC", "Microsoft Corporation", "Amazon.com", "Cloudflare, Inc."]

# ==========================================
# 2. 資料庫初始化 (Database Initialization)
# ==========================================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # 建立黑名單 (blocked_ips)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            ip_address TEXT UNIQUE NOT NULL, 
            reason TEXT NOT NULL, 
            country TEXT, 
            city TEXT, 
            isp TEXT, 
            org TEXT, 
            timestamp DATETIME DEFAULT (datetime('now', 'localtime'))
        )
    ''')

    # 建立觀察名單 (observed_ips) - 包含風險評分機制
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS observed_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            ip_address TEXT UNIQUE NOT NULL, 
            risk_score INTEGER DEFAULT 0, 
            hit_count INTEGER DEFAULT 0, 
            last_reason TEXT, 
            country TEXT, 
            city TEXT, 
            org TEXT, 
            last_seen DATETIME DEFAULT (datetime('now', 'localtime'))
        )
    ''')

    # ==========================
    # 預設資料寫入
    # ==========================
    # 觀察名單預設資料
    mock_observations = [
        ('2.19.205.255', 75, 1, '多次 SSH 登入失敗', 'Russia', 'Moscow', 'Akamai Technologies'),
        ('2.19.205.180', 65, 1, '多次 SSH 登入失敗', 'Russia', 'Moscow', 'Akamai Technologies'),
        ('8.8.8.8', 20, 1, '初次查詢紀錄', 'United States', 'Ashburn', 'Google LLC')
    ]
    
    for ip, score, hits, reason, country, city, org in mock_observations:
        cursor.execute("""
            INSERT OR IGNORE INTO observed_ips (ip_address, risk_score, hit_count, last_reason, country, city, org) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, score, hits, reason, country, city, org))

    # 黑名單預設資料
    cursor.execute("""
        INSERT OR IGNORE INTO blocked_ips (ip_address, reason, country, city, isp, org) 
        VALUES ('1.2.3.4', '歷史 Botnet 攻擊紀錄', 'United States', 'San Jose', 'Cloudflare', 'Cloudflare, Inc.')
    """)

    conn.commit()
    conn.close()

# 啟動時立即執行初始化
init_db()

# ==========================================
# 3. 核心工具 (MCP Tools)
# ==========================================

@mcp.tool()
async def lookup_ip_geolocation(ip: str) -> str:
    """查詢指定 IP 的地理位置與 ISP 資訊"""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,query"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=5.0)
            data = response.json()
            if data.get('status') == 'fail': 
                return f"查詢失敗: {data.get('message', '未知錯誤')}"
            return f"國家: {data.get('country', '未知')}, 城市: {data.get('city', '未知')}, ISP: {data.get('isp', '未知')}, 組織: {data.get('org', '未知')}"
        except Exception as e:
            return f"連線錯誤: {str(e)}"

@mcp.tool()
def analyze_and_update_reputation(ip: str, geo_country: str = "", geo_isp: str = "", geo_org: str = "") -> str:
    """
    [核心工具] 查詢內部資料庫並根據外部傳入的 Geo-IP 情報進行「動態風險評分計算」
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # 1. 檢查是否已在黑名單
    cursor.execute("SELECT reason, timestamp FROM blocked_ips WHERE ip_address = ?", (ip,))
    blocked = cursor.fetchone()
    if blocked:
        conn.close()
        return f"【狀態：已封鎖 🚫】此 IP 已在黑名單中。原因：{blocked[0]}，時間：{blocked[1]}"

    # 2. 取得觀察名單紀錄
    cursor.execute("SELECT risk_score, hit_count, last_reason FROM observed_ips WHERE ip_address = ?", (ip,))
    observed = cursor.fetchone()
    
    # 初始化計分變數
    base_score = observed[0] if observed else 20
    hits = observed[1] if observed else 0
    reason = observed[2] if observed else "新發現的可疑 IP"
    
    score_adjustment = 0
    adjustment_reasons = []

    # 動態加權邏輯
    if any(country in geo_country for country in HIGH_RISK_COUNTRIES):
        score_adjustment += 30
        adjustment_reasons.append("來自高風險國家 (+30)")
    if any(isp in geo_isp for isp in HIGH_RISK_ISPS):
        score_adjustment += 20
        adjustment_reasons.append("使用常見跳板 ISP (+20)")
    if any(org in geo_org for org in TRUSTED_ORGS):
        score_adjustment -= 40
        adjustment_reasons.append("知名可信組織 (-40)")

    final_score = max(0, min(100, base_score + score_adjustment))
    new_hits = hits + 1
    
    # ==========================================
    # 從傳入的字串解析地理資訊 (防呆設計)
    # ==========================================
    parsed_country = "未知"
    parsed_city = "未知"
    parsed_org = "未知"
    
    if geo_country:
        c_match = re.search(r"國家:\s*([^,]+)", geo_country)
        if c_match: parsed_country = c_match.group(1).strip()
        
        ci_match = re.search(r"城市:\s*([^,]+)", geo_country)
        if ci_match: parsed_city = ci_match.group(1).strip()
        
        o_match = re.search(r"組織:\s*([^,]+)", geo_country)
        if o_match: parsed_org = o_match.group(1).strip()

    # 寫入或更新資料庫
    if observed:
        cursor.execute("""
            UPDATE observed_ips 
            SET risk_score = ?, hit_count = ?, last_seen = datetime('now', 'localtime'),
                country = ?, city = ?, org = ?
            WHERE ip_address = ?
        """, (final_score, new_hits, parsed_country, parsed_city, parsed_org, ip))
    else:
        cursor.execute("""
            INSERT INTO observed_ips (ip_address, risk_score, hit_count, last_reason, country, city, org, last_seen) 
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
        """, (ip, final_score, new_hits, reason, parsed_country, parsed_city, parsed_org))
    
    conn.commit()
    conn.close()
    
    # 產生分析報告回傳給 Agent
    status = "CRITICAL" if final_score >= 80 else "WARNING"
    report = f"【狀態：重點觀察 ⚠️】風險等級：{status}\n"
    report += f"- 最終評分：{final_score} (歷史基礎分: {base_score}, 本次調整: {score_adjustment})\n"
    if adjustment_reasons:
        report += f"- 調整原因：{', '.join(adjustment_reasons)}\n"
    report += f"- 累積偵測：{new_hits} 次"
    
    return report

@mcp.tool()
def block_ip_tool(ip: str, reason: str, country: str = "未知", city: str = "未知", org: str = "未知") -> str:
    """[企業防火牆 API] 將 IP 移入黑名單"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # 寫入黑名單
        cursor.execute("""
            INSERT INTO blocked_ips (ip_address, reason, country, city, org) 
            VALUES (?, ?, ?, ?, ?)
        """, (ip, reason, country, city, org))
        
        # 執行成功後 移出觀察名單
        cursor.execute("DELETE FROM observed_ips WHERE ip_address = ?", (ip,))
        
        conn.commit()
        conn.close()
        return f"✅ 成功將 IP {ip} 永久封鎖並移出觀察名單。"
        
    except sqlite3.IntegrityError:
        return f"⚠️ IP {ip} 已經在黑名單中了。"
    except Exception as e:
        return f"❌ 執行失敗: {str(e)}"