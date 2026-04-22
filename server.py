from mcp.server.fastmcp import FastMCP
import httpx
import sqlite3
import os

# 初始化 MCP Server
mcp = FastMCP("ThreatIntelServer")

# 定義 SQLite 資料庫檔案名稱
DB_FILE = "threat_intel.db"

def init_db():
    """初始化 SQLite 資料庫，建立黑名單資料表"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # 建立一個儲存惡意 IP 的資料表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # 預先塞入一筆假資料，一開始測試 1.2.3.4 就能看到效果
    cursor.execute("INSERT OR IGNORE INTO blocked_ips (ip_address, reason) VALUES ('1.2.3.4', '歷史 Botnet 攻擊紀錄')")
    conn.commit()
    conn.close()
    print("✅ 內部情資資料庫 (SQLite) 初始化完成！")

# 伺服器啟動時自動建立資料庫
init_db()

# ==========================================
# 工具 1: 真實的 IP 地理位置查詢 
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
# 工具 2: 查詢內部 SQLite 信譽資料庫
# ==========================================
@mcp.tool()
def query_internal_reputation_db(ip: str) -> str:
    """
    查詢公司內部的威脅情資資料庫 (SQLite DB)
    這包含公司歷史紀錄中的黑名單 IP 與攻擊紀錄
    """
    # 內部網段防呆機制
    if ip.startswith("192.168") or ip.startswith("10."):
        return "【內部資料庫】此為內部 IP，信譽良好 (Safe)。"
    elif ip == "8.8.8.8":
        return "【內部資料庫】Google DNS，白名單信任節點。"

    # 改為查詢真實的 SQLite 資料庫
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT reason, timestamp FROM blocked_ips WHERE ip_address = ?", (ip,))
    result = cursor.fetchone()
    conn.close()

    if result:
        reason, timestamp = result
        return f"【內部資料庫】⚠️ 警示！此 IP 在黑名單中。\n封鎖時間: {timestamp}\n封鎖原因: {reason}\n風險等級: Critical。"
    else:
        return "【內部資料庫】無此 IP 的內部歷史紀錄 (未被封鎖)。"

# ==========================================
# 工具 3: 將惡意 IP 寫入防火牆黑名單 
# ==========================================
@mcp.tool()
def block_malicious_ip(ip: str, reason: str) -> str:
    """
    [企業防火牆 API] 將惡意 IP 加入黑名單資料庫，阻斷其連線
    只有在確定是惡意攻擊時才呼叫此工具
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # 將 IP 寫入資料庫
        cursor.execute("INSERT INTO blocked_ips (ip_address, reason) VALUES (?, ?)", (ip, reason))
        conn.commit()
        conn.close()
        return f"✅ 成功將 IP {ip} 加入防火牆黑名單。原因：{reason}"
    except sqlite3.IntegrityError:
        return f"⚠️ IP {ip} 已經在黑名單中了，無需重複加入。"
    except Exception as e:
        return f"❌ 寫入資料庫失敗: {str(e)}"
    
# uvicorn server:mcp.sse_app --reload --port 8000