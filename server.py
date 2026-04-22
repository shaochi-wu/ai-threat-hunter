from mcp.server.fastmcp import FastMCP
import httpx
import sqlite3
import os
from datetime import datetime

# 初始化 MCP Server
mcp = FastMCP("ThreatIntelServer")

# 定義 SQLite 資料庫檔案名稱
DB_FILE = "threat_intel.db"

def init_db():
    """初始化 SQLite 資料庫，建立黑名單資料表"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # 建立一個儲存惡意 IP 的資料表，新增地理情資欄位
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            country TEXT,
            city TEXT,
            isp TEXT,
            org TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 如果資料表已存在但沒新欄位，手動補上
    columns = [row[1] for row in cursor.execute("PRAGMA table_info(blocked_ips)")]
    new_cols = ["country", "city", "isp", "org"]
    for col in new_cols:
        if col not in columns:
            cursor.execute(f"ALTER TABLE blocked_ips ADD COLUMN {col} TEXT")

    # 預先塞入一筆帶有詳細資訊的假資料，方便測試
    cursor.execute("""
        INSERT OR IGNORE INTO blocked_ips (ip_address, reason, country, city, isp, org) 
        VALUES ('1.2.3.4', '歷史 Botnet 攻擊紀錄', 'United States', 'San Jose', 'Cloudflare', 'Cloudflare, Inc.')
    """)
    conn.commit()
    conn.close()
    print("✅ 內部情資資料庫 (SQLite) 與欄位初始化完成！")

# 伺服器啟動時自動建立資料庫
init_db()

# ==========================================
# 工具 1: 真實的 IP 地理位置查詢 (保持不變)
# ==========================================
@mcp.tool()
async def lookup_ip_geolocation(ip: str) -> str:
    """
    使用外部真實 API 查詢 IP 位址的地理位置、ISP 與組織名稱
    用於分析 IP 是否來自高風險國家或已知的雲端服務商
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,query"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=5.0)
            data = response.json()
            if data['status'] == 'fail':
                return f"查詢失敗: {data.get('message', '未知錯誤')}"
            
            return f"""
            【真實 IP 情報】
            - IP: {data['query']}
            - 國家: {data['country']}
            - 城市: {data['city']}
            - ISP: {data['isp']}
            - 組織: {data['org']}
            """
        except Exception as e:
            return f"連線錯誤: {str(e)}"

# ==========================================
# 工具 2: 查詢內部 SQLite 信譽資料庫 (升級版)
# ==========================================
@mcp.tool()
def query_internal_reputation_db(ip: str) -> str:
    """
    查詢公司內部的威脅情資資料庫 (SQLite DB)。
    這包含公司歷史紀錄中的黑名單 IP、地理資訊與封鎖原因。
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # 增加讀取地理資訊欄位
    cursor.execute("SELECT reason, timestamp, country, city, isp, org FROM blocked_ips WHERE ip_address = ?", (ip,))
    result = cursor.fetchone()
    conn.close()

    if result:
        reason, timestamp, country, city, isp, org = result
        return f"""【內部資料庫】⚠️ 警示！此 IP 已存在於防火牆黑名單中。
- 目前狀態：已封鎖阻斷
- 封鎖時間：{timestamp}
- 封鎖原因：{reason}
- 來源情報：{country} / {city} ({org})
[系統提示] 此 IP 已處於封鎖狀態，絕對不要重複呼叫 block_ip_tool。"""

    # 預設白名單規則
    if ip.startswith("192.168") or ip.startswith("10."):
        return "【內部資料庫】此為內部 IP，信譽良好 (Safe)。"
    elif ip == "8.8.8.8":
        return "【內部資料庫】Google DNS，白名單信任節點。"
        
    return "【內部資料庫】無此 IP 的內部歷史紀錄 (未被封鎖)。"

# ==========================================
# 工具 3: 將惡意 IP 寫入防火牆黑名單 (更名與功能升級)
# ==========================================
@mcp.tool()
def block_ip_tool(
    ip: str, 
    reason: str, 
    country: str = "未提供", 
    city: str = "未提供", 
    isp: str = "未提供", 
    org: str = "未提供"
) -> str:
    """
    [企業防火牆 API] 將惡意 IP 加入黑名單資料庫，阻斷其連線。
    呼叫此工具前，請先透過 lookup_ip_geolocation 取得地理資訊。
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # 寫入包含地理資訊的完整資料
        cursor.execute("""
            INSERT INTO blocked_ips (ip_address, reason, country, city, isp, org, timestamp) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip, reason, country, city, isp, org, current_time))
        conn.commit()
        conn.close()
        return f"✅ 成功將 IP {ip} 加入防火牆黑名單。來源：{country} ({org})"
    except sqlite3.IntegrityError:
        return f"⚠️ IP {ip} 已經在黑名單中了，無需重複加入。"
    except Exception as e:
        return f"❌ 寫入資料庫失敗: {str(e)}"