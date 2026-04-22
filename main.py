import os
import ast
import asyncio
import sqlite3
from contextlib import AsyncExitStack
from dotenv import load_dotenv

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_groq import ChatGroq
from langchain_text_splitters import CharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.tools import tool

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

from langgraph.graph import StateGraph, MessagesState, START, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

from mcp import ClientSession
from mcp.client.sse import sse_client 

load_dotenv()

# ==========================================
# 1. RAG 與 MCP 工具定義
# ==========================================
def init_rag_system():
    try:
        embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        # 改為從本地端載入已建好的 FAISS 資料庫
        # allow_dangerous_deserialization 是 FAISS 為了安全性要求的明確授權
        vector_db = FAISS.load_local("faiss_index", embeddings, allow_dangerous_deserialization=True)
        print("✅ 成功載入本地知識庫 (FAISS)！")
        
        # 設定檢索器：每次只取最相關的 2 個 chunk (k=2) 送給 LLM，節省 Token
        return vector_db.as_retriever(search_kwargs={"k": 2})
    except Exception as e:
        print(f"❌ 載入知識庫失敗: {e}")
        print("💡 請先執行 `python ingest.py` 來建立知識庫！")
        raise e

retriever = init_rag_system()

async def _call_mcp_tool(tool_name: str, arguments: dict):
    url = "http://localhost:8000/sse"
    async with AsyncExitStack() as stack:
        try:
            client = await stack.enter_async_context(sse_client(url))
            session = await stack.enter_async_context(ClientSession(client[0], client[1]))
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)
            return result.content[0].text
        except Exception as e:
            return f"MCP 連線錯誤: {str(e)}"

@tool
async def check_ip_intelligence(ip_address: str):
    """[安全工具] 綜合查詢 IP 威脅情資與地理位置。"""
    geo_info = await _call_mcp_tool("lookup_ip_geolocation", {"ip": ip_address})
    db_info = await _call_mcp_tool("query_internal_reputation_db", {"ip": ip_address}) 
    return f"{geo_info}\n\n{db_info}"

@tool
async def search_security_sop(query: str):
    """[安全工具] 查詢內部資安 SOP 文件。"""
    docs = retriever.invoke(query)
    return "\n\n".join([doc.page_content for doc in docs])

# 新增封鎖 IP 的工具 (串接 server.py 的新功能)
@tool
async def block_ip_tool(ip: str, reason: str):
    """[敏感工具] 將惡意 IP 加入防火牆黑名單。必須附上封鎖原因 (reason)。"""
    return await _call_mcp_tool("block_malicious_ip", {"ip": ip, "reason": reason})

# ==========================================
# 2. LangGraph 拓撲重構 (區分安全與敏感節點)
# ==========================================
# 將工具分類
safe_tools = [check_ip_intelligence, search_security_sop]
sensitive_tools = [block_ip_tool]
all_tools = safe_tools + sensitive_tools

# llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
# llm = ChatOllama(model="qwen3.5:2b", temperature=0)
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)

# 動態載入外部 System Prompt
prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "system_prompt.md")
try:
    with open(prompt_path, "r", encoding="utf-8") as f:
        system_prompt_content = f.read()
except FileNotFoundError:
    print(f"❌ 找不到 System Prompt 檔案: {prompt_path}")

sys_msg = SystemMessage(content=system_prompt_content)

async def agent_node(state: MessagesState):
    print("\n" + "="*45)
    print("🧠 --- 進入 Agent 思考節點 ---")
    
    llm_with_tools = llm.bind_tools(all_tools)
    result = await llm_with_tools.ainvoke([sys_msg] + state["messages"])
    
    # 判斷 Agent 決定做什麼，並印出漂亮的 Log
    if result.tool_calls:
        print("🛠️ --- Agent 決定呼叫工具 ---")
        for tc in result.tool_calls:
            print(f"   🔧 工具名稱: {tc['name']}")
            print(f"   📦 傳入參數: {tc['args']}")
    else:
        print("💬 --- Agent 決定直接回覆 (不呼叫工具) ---")
        
    print("="*45 + "\n")
    
    return {"messages": [result]}

# 建立自定義的工具路由函數
def route_tools(state: MessagesState):
    messages = state["messages"]
    last_message = messages[-1]
    
    if not last_message.tool_calls:
        return END
    
    # 檢查是否包含敏感工具 (封鎖 IP)
    for tc in last_message.tool_calls:
        if tc["name"] in [t.name for t in sensitive_tools]:
            return "sensitive_tools_node"
            
    return "safe_tools_node"

builder = StateGraph(MessagesState)
builder.add_node("agent", agent_node)
builder.add_node("safe_tools_node", ToolNode(safe_tools))
builder.add_node("sensitive_tools_node", ToolNode(sensitive_tools))

builder.add_edge(START, "agent")
# 根據工具性質動態路由
builder.add_conditional_edges("agent", route_tools, ["safe_tools_node", "sensitive_tools_node", END])
builder.add_edge("safe_tools_node", "agent")
builder.add_edge("sensitive_tools_node", "agent")

memory = MemorySaver()
# 設定中斷點：在進入 sensitive_tools_node 之前凍結 Graph
graph = builder.compile(checkpointer=memory, interrupt_before=["sensitive_tools_node"])

# 輸出清洗函數 (保持不變)
def parse_gemini_output(content):
    if isinstance(content, str):
        if content.strip().startswith("[") or content.strip().startswith("{"):
            try: content = ast.literal_eval(content)
            except: pass
    if isinstance(content, list):
        return "".join([item.get('text', '') if isinstance(item, dict) else item for item in content])
    return str(content)

# ==========================================
# 3. FastAPI API 設計
# ==========================================
app = FastAPI(title="AI Threat Hunter API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class ChatRequest(BaseModel):
    message: str
    session_id: str

class ApproveRequest(BaseModel):
    session_id: str
    approved: bool

@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    try:
        config = {"configurable": {"thread_id": request.session_id}}
        inputs = {"messages": [HumanMessage(content=request.message)]}
        result = await graph.ainvoke(inputs, config=config)
        
        # 檢查 Graph 是否卡在中斷點
        state = await graph.aget_state(config)
        if state.next and "sensitive_tools_node" in state.next:
            last_msg = state.values["messages"][-1]
            tool_call = last_msg.tool_calls[0]
            ip_to_block = tool_call["args"].get("ip", "未知 IP")
            reason = tool_call["args"].get("reason", "未知原因")
            
            return {
                "status": "requires_approval", 
                "ip": ip_to_block,
                "reason": reason,
                "reply": f"⚠️ **系統警報**\nAgent 建議封鎖 IP **{ip_to_block}**。\n**原因：** {reason}\n\n請指示是否授權執行此封鎖操作？"
            }

        last_message = result["messages"][-1]
        clean_content = parse_gemini_output(last_message.content)
        return {"status": "success", "reply": clean_content}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

# 新增審批 API
@app.post("/api/approve")
async def approve_endpoint(request: ApproveRequest):
    try:
        config = {"configurable": {"thread_id": request.session_id}}
        state = await graph.aget_state(config)
        
        if not state.next or "sensitive_tools_node" not in state.next:
            return {"status": "error", "message": "目前沒有等待審批的操作。"}

        if request.approved:
            # 使用者同意：傳入 None 讓 Graph 繼續執行原本凍結的工具
            result = await graph.ainvoke(None, config=config)
        else:
            # 使用者拒絕：手動構造一個 ToolMessage 告訴 Agent 執行失敗/被拒絕
            last_msg = state.values["messages"][-1]
            tool_call = last_msg.tool_calls[0]
            
            reject_msg = ToolMessage(
                tool_call_id=tool_call["id"],
                name=tool_call["name"],
                content="[拒絕執行] 人類分析師已否決此封鎖操作，請回報使用者操作已取消，並提供其他建議。"
            )
            # 將這個拒絕訊息「注入」到系統狀態中，假裝 sensitive_tools_node 執行完了
            await graph.aupdate_state(config, {"messages": [reject_msg]}, as_node="sensitive_tools_node")
            # 讓 Graph 繼續跑 (Agent 會看到拒絕訊息並產生新回覆)
            result = await graph.ainvoke(None, config=config)

        last_message = result["messages"][-1]
        clean_content = parse_gemini_output(last_message.content)
        return {"status": "success", "reply": clean_content}
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

# ==========================================
# 4. 前端 API (獨立於 Agent 之外)
# ==========================================
DB_FILE = "threat_intel.db"

@app.get("/api/blacklist")
async def get_blacklist():
    """獲取目前黑名單列表"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # 依時間遞減排序，最新的在最上面
        cursor.execute("SELECT ip_address, reason, timestamp FROM blocked_ips ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        conn.close()
        
        return [{"ip": r[0], "reason": r[1], "timestamp": r[2]} for r in rows]
    except Exception as e:
        return []

@app.delete("/api/blacklist/{ip}")
async def remove_from_blacklist(ip: str):
    """手動解鎖 (刪除) 指定 IP"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit()
    changes = conn.total_changes
    conn.close()
    
    if changes > 0:
        return {"status": "success", "message": f"{ip} 已解除封鎖"}
    return {"status": "error", "message": "找不到該 IP"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)