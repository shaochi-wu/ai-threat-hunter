from mcp.server.fastmcp import FastMCP
import httpx

# 初始化 MCP Server
# "ThreatIntelServer" 是這台 Server 的名字
mcp = FastMCP("ThreatIntelServer")

# ==========================================
# 工具 1: 真實的 IP 地理位置查詢 (使用 ip-api.com 免費 API)
# ==========================================
@mcp.tool()
async def lookup_ip_geolocation(ip: str) -> str:
    """
    使用外部真實 API 查詢 IP 位址的地理位置、ISP 與組織名稱。
    用於分析 IP 是否來自高風險國家或已知的雲端服務商。
    """
    # 這是真實的 API 請求，不是 Mock！
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,query"
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, timeout=5.0)
            data = response.json()
            
            if data['status'] == 'fail':
                return f"查詢失敗: {data.get('message', '未知錯誤')}"
            
            # 整理回傳資訊
            return f"""
            【真實 IP 情報】
            - IP: {data['query']}
            - 國家: {data['country']}
            - 城市: {data['city']}
            - ISP (網路服務商): {data['isp']}
            - 組織: {data['org']}
            - AS Number: {data['as']}
            """
        except Exception as e:
            return f"連線錯誤: {str(e)}"

# ==========================================
# 工具 2: 模擬的內部信譽資料庫 (保留你的 Mock 邏輯)
# ==========================================
@mcp.tool()
def query_internal_reputation_db(ip: str) -> str:
    """
    查詢公司內部的威脅情資資料庫 (Threat Intelligence DB)。
    這包含公司歷史紀錄中的黑名單 IP 與攻擊紀錄。
    """
    # 這裡保留模擬邏輯，因為這是「內部資料」
    if ip.startswith("192.168"):
        return "【內部資料庫】此為內部 IP，信譽良好 (Safe)。"
    elif ip == "1.2.3.4":
        return "【內部資料庫】警示！此 IP 曾於 2024-01-20 發動 Botnet 攻擊，風險等級: Critical。"
    elif ip == "8.8.8.8":
        return "【內部資料庫】Google DNS，白名單信任節點。"
    else:
        return "【內部資料庫】無此 IP 的內部歷史紀錄。"

# 啟動指令
# uvicorn server:mcp.sse_app --reload --port 8000