import os
import re
import pickle
import sqlite3
from contextlib import AsyncExitStack

from dotenv import load_dotenv
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from mcp import ClientSession
from mcp.client.sse import sse_client 

from langchain_groq import ChatGroq
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_classic.retrievers import EnsembleRetriever
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, ToolMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from langgraph.graph import StateGraph, MessagesState, START, END
from langgraph.prebuilt import ToolNode
from langgraph.checkpoint.memory import MemorySaver

load_dotenv()

# ==========================================
# 1. 系統與 LLM 設定 
# ==========================================
DB_FILE = "threat_intel.db"
# llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)
# llm = ChatOllama(model="qwen3.5:2b", temperature=0)
llm = ChatGroq(model="llama-3.3-70b-versatile", temperature=0)

def load_prompt(filename):
    path = os.path.join(os.path.dirname(__file__), "prompts", filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

# ==========================================
# 2. Hybrid Search RAG 初始化 
# ==========================================
def init_rag_system():
    print("初始化 Hybrid RAG 系統...")
    
    # 1：FAISS (抓語意)
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vector_db = FAISS.load_local("faiss_index", embeddings, allow_dangerous_deserialization=True)
    faiss_retriever = vector_db.as_retriever(search_kwargs={"k": 6}) 

    # 2：BM25 (抓關鍵字)
    try:
        with open("faiss_index/bm25_index.pkl", "rb") as f:
            bm25_retriever = pickle.load(f)
            bm25_retriever.k = 6 
    except FileNotFoundError:
        print("⚠️ 找不到 BM25 索引，請先執行 ingest.py！")
        return faiss_retriever

    # 融合：Ensemble Retriever
    hybrid_retriever = EnsembleRetriever(
        retrievers=[bm25_retriever, faiss_retriever],
        weights=[0.5, 0.5] 
    )
    return hybrid_retriever

retriever = init_rag_system()

# ==========================================
# 3. 工具定義 (MCP & Local Tools)
# ==========================================
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
    """[安全工具] 綜合查詢 IP 威脅情資 會自動更新觀察名單分數"""
    geo_info = await _call_mcp_tool("lookup_ip_geolocation", {"ip": ip_address})
    db_info = await _call_mcp_tool("analyze_and_update_reputation", {
        "ip": ip_address,
        "geo_country": geo_info,
        "geo_isp": geo_info,
        "geo_org": geo_info
    }) 
    return f"【Geo-IP】\n{geo_info}\n\n【DB-Info】\n{db_info}"

@tool
async def search_security_sop(query: str):
    """[安全工具] 查詢內部資安 SOP 文件"""
    docs = retriever.invoke(query)
    return "\n\n".join([doc.page_content for doc in docs])

@tool
async def block_ip_tool(ip: str, reason: str, country: str, city: str, org: str):
    """
    [敏感工具] 將惡意 IP 加入防火牆黑名單
    【強制規範】必須先查出完整的地理資訊 reason 必須具體
    """
    payload = {"ip": ip, "reason": reason, "country": country, "city": city, "org": org}
    return await _call_mcp_tool("block_ip_tool", payload)

safe_tools = [check_ip_intelligence, search_security_sop]
sensitive_tools = [block_ip_tool]

# ==========================================
# 4. Agent 節點邏輯 (Multi-Agent Nodes)
# ==========================================
class AgentState(MessagesState):
    next_node: str

async def researcher_node(state: AgentState):
    prompt = ChatPromptTemplate.from_messages([
        ("system", load_prompt("researcher_prompt.md")),
        MessagesPlaceholder(variable_name="messages"),
    ])
    result = await (prompt | llm.bind_tools(safe_tools)).ainvoke(state)
    return {"messages": [result]}

async def responder_node(state: AgentState):
    prompt = ChatPromptTemplate.from_messages([
        ("system", load_prompt("responder_prompt.md")),
        MessagesPlaceholder(variable_name="messages"),
    ])
    # 強迫輸出 Tool Call，斷絕閒聊
    result = await (prompt | llm.bind_tools(sensitive_tools, tool_choice="any")).ainvoke(state)
    return {"messages": [result]}

async def supervisor_node(state: AgentState):
    prompt = ChatPromptTemplate.from_messages([
        ("system", load_prompt("supervisor_prompt.md")),
        MessagesPlaceholder(variable_name="messages"),
    ])
    result = await (prompt | llm).ainvoke(state)
    if result.content is None:
        result.content = ""

    messages = state["messages"]
    has_intel, score, has_blocked_or_rejected = False, 0, False
    latest_user_msg = ""

    # 解析對話歷史狀態
    for m in reversed(messages):
        if isinstance(m, HumanMessage):
            if "[系統稽核]" in str(m.content): continue
            latest_user_msg = str(m.content)
            break 
            
        if isinstance(m, ToolMessage):
            if m.name == "check_ip_intelligence":
                has_intel = True
                match = re.search(r"(?:最終評分|評分|Risk Score)[：:]\s*(\d+)", str(m.content), re.IGNORECASE)
                if match: score = int(match.group(1))
            elif m.name == "block_ip_tool":
                has_blocked_or_rejected = True

    # 意圖與情境判斷
    is_manual_block = "封鎖" in latest_user_msg or "block" in latest_user_msg.lower()
    has_ip = bool(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", latest_user_msg))
    next_node = "FINISH"

    # 絕對狀態機邏輯
    if has_ip:
        if not has_intel:
            next_node = "Researcher"
            result.content = "Decision: Researcher" 
        elif has_intel and not has_blocked_or_rejected:
            if score >= 80 or is_manual_block:
                next_node = "Responder"
                result.content = "Decision: Responder" 
            else:
                next_node = "FINISH"
                if "Decision: FINISH" not in result.content: result.content += "\nDecision: FINISH"
        elif has_intel and has_blocked_or_rejected:
            next_node = "FINISH"
            if "Decision: FINISH" not in result.content: result.content += "\nDecision: FINISH"
    else:
        if "FINISH" in result.content.upper():
            next_node = "FINISH"
            if "Decision: FINISH" not in result.content: result.content += "\nDecision: FINISH"
        else:
            next_node = "Researcher"
            if "Decision: Researcher" not in result.content: result.content = "Decision: Researcher"

    return {"next_node": next_node, "messages": [result]}

async def reflection_node(state: AgentState):
    messages = state["messages"]
    last_msg = messages[-1]
    
    if not hasattr(last_msg, "tool_calls") or not last_msg.tool_calls:
        return {}

    latest_user_msg = ""
    for m in reversed(messages):
        if isinstance(m, HumanMessage) and "[系統稽核]" not in str(m.content):
            latest_user_msg = str(m.content)
            break
    
    is_manual_block = "封鎖" in latest_user_msg or "block" in latest_user_msg.lower()

    last_tool_output = next((str(m.content) for m in reversed(messages) if isinstance(m, ToolMessage) and m.name == "check_ip_intelligence"), "")
    score_match = re.search(r"最終評分[：:]\s*(\d+)", last_tool_output)
    current_score = int(score_match.group(1)) if score_match else 0

    if current_score < 80 and not is_manual_block:
        return {"messages": [HumanMessage(content=f"[系統稽核] 攔截！當前分數 {current_score} 未達 80 分。")]}
    
    return {}

# ==========================================
# 5. LangGraph 路由與組裝 (Graph Orchestration)
# ==========================================
def route_main(state: AgentState):
    return state["next_node"] if state["next_node"] != "FINISH" else END

def route_researcher(state: AgentState):
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls: return "safe_tools"
    return "supervisor"

def route_responder(state: AgentState):
    last_msg = state["messages"][-1]
    if hasattr(last_msg, "tool_calls") and last_msg.tool_calls: return "reflect"
    return "supervisor"

def route_reflect(state: AgentState):
    last_msg = state["messages"][-1]
    content = last_msg.content or ""
    if isinstance(last_msg, HumanMessage) and "[系統稽核]" in str(content): return "supervisor"
    return "sensitive_tools"

builder = StateGraph(AgentState)
builder.add_node("supervisor", supervisor_node)
builder.add_node("Researcher", researcher_node)
builder.add_node("Responder", responder_node)
builder.add_node("safe_tools", ToolNode(safe_tools))
builder.add_node("sensitive_tools", ToolNode(sensitive_tools))
builder.add_node("reflect", reflection_node)

builder.add_edge(START, "supervisor")
builder.add_conditional_edges("supervisor", route_main, {"Researcher": "Researcher", "Responder": "Responder", END: END})
builder.add_conditional_edges("Researcher", route_researcher, {"safe_tools": "safe_tools", "supervisor": "supervisor"})
builder.add_conditional_edges("Responder", route_responder, {"reflect": "reflect", "supervisor": "supervisor"})
builder.add_edge("safe_tools", "supervisor")
builder.add_conditional_edges("reflect", route_reflect, {"supervisor": "supervisor", "sensitive_tools": "sensitive_tools"})
builder.add_edge("sensitive_tools", "supervisor")

memory = MemorySaver()
graph = builder.compile(checkpointer=memory, interrupt_before=["sensitive_tools"])

# ==========================================
# 6. FastAPI 伺服器端點 (API Endpoints)
# ==========================================
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class ChatRequest(BaseModel):
    message: str
    session_id: str

class ApproveRequest(BaseModel):
    session_id: str
    approved: bool

@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    print(f"\n\n{'='*50}")
    print(f"[新任務啟動] Session: {request.session_id}")
    print(f"[使用者輸入] {request.message}")
    print(f"{'='*50}")

    try:
        config = {"configurable": {"thread_id": request.session_id}}
        inputs = {"messages": [HumanMessage(content=request.message)]}
        steps = []
        
        async for event in graph.astream(inputs, config=config, stream_mode="updates"):
            for node_name, node_state in event.items():
                print(f"\n[進入節點] -> {node_name}")
                if node_state and isinstance(node_state, dict) and "messages" in node_state and len(node_state["messages"]) > 0:
                    msg = node_state["messages"][-1]
                    if isinstance(msg, AIMessage):
                        if msg.tool_calls:
                            step_desc = f"指派工具：{msg.tool_calls[0]['name']}"
                            steps.append({"type": "thought", "content": step_desc})
                            print(f"[AI 決策] 準備呼叫工具 ➔ {msg.tool_calls[0]['name']}")
                            print(f"[參數] {msg.tool_calls[0]['args']}")
                        else:
                            content_str = str(msg.content) if msg.content else "無文字輸出"
                            print(f"[AI 輸出] {content_str[:50]}...") 
                    elif isinstance(msg, ToolMessage):
                        steps.append({"type": "tool_output", "tool": msg.name, "content": msg.content})
                        print(f"[工具回傳] {msg.name} (結果長度: {len(str(msg.content))} 字元)")
                    elif isinstance(msg, HumanMessage) and msg.content and "[系統稽核]" in str(msg.content):
                        steps.append({"type": "reflection", "content": msg.content})
                        print(f"[稽核攔截] {msg.content}")

        state = await graph.aget_state(config)
        if state.next and "sensitive_tools" in state.next:
            block_msg = next((m for m in reversed(state.values["messages"]) if isinstance(m, AIMessage) and m.tool_calls), None)
            if block_msg:
                args = block_msg.tool_calls[0].get("args", {})
                reason_val = args.get("reason", "未提供原因")
                human_msg = next((m.content for m in reversed(state.values["messages"]) if isinstance(m, HumanMessage)), "")
                match = re.search(r"原因為\s*(.+)", str(human_msg))
                if match:
                    reason_val = match.group(1).strip()
                    args["reason"] = reason_val
                print(f"\n⏸[流程暫停] 等待人類審批 (HITL)...")
                return {
                    "status": "requires_approval",
                    "ip": args.get("ip", "未知 IP"),
                    "reason": reason_val,
                    "steps": steps,
                    "reply": f"**高風險警報**\n應變員發起封鎖請求：\n- IP: **{args.get('ip', '未知')}**\n請指示是否授權？"
                }

        last_msg = state.values["messages"][-1]
        final_reply = getattr(last_msg, "content", str(last_msg))
        if isinstance(final_reply, list) and len(final_reply) > 0: final_reply = final_reply[0].get("text", "")
        final_reply = re.sub(r"Decision:\s*(FINISH|Researcher|Responder)", "", str(final_reply) or "", flags=re.IGNORECASE).strip()
        
        print(f"\n[任務完成] 準備回傳結果給前端")
        return {"status": "success", "reply": final_reply, "steps": steps}
        
    except Exception as e:
        print(f"\n❌ [系統崩潰] {str(e)}")
        return {"status": "error", "message": f"伺服器錯誤: {str(e)}"}
    
@app.post("/api/approve")
async def approve_endpoint(request: ApproveRequest):
    try:
        config = {"configurable": {"thread_id": request.session_id}}
        state = await graph.aget_state(config)
        if not state.next: return {"status": "error", "message": "無等待中操作"}

        if request.approved:
            last_msg = next(m for m in reversed(state.values["messages"]) if isinstance(m, AIMessage) and m.tool_calls)
            human_msg = next((m.content for m in reversed(state.values["messages"]) if isinstance(m, HumanMessage)), "")
            match = re.search(r"原因為\s*(.+)", str(human_msg))
            if match:
                last_msg.tool_calls[0]["args"]["reason"] = match.group(1).strip()
                await graph.aupdate_state(config, {"messages": [last_msg]})
            async for _ in graph.astream(None, config=config): pass
        else:
            last_msg = next(m for m in reversed(state.values["messages"]) if isinstance(m, AIMessage) and m.tool_calls)
            reject_msg = ToolMessage(tool_call_id=last_msg.tool_calls[0]["id"], name=last_msg.tool_calls[0]["name"], content="[分析師拒絕] 取消封鎖，維持觀察。")
            await graph.aupdate_state(config, {"messages": [reject_msg]}, as_node="sensitive_tools")
            async for _ in graph.astream(None, config=config): pass
        
        final_state = await graph.aget_state(config)
        final_reply = re.sub(r"Decision:\s*(FINISH|Researcher|Responder)", "", final_state.values["messages"][-1].content or "").strip()
        return {"status": "success", "reply": final_reply}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/blacklist")
async def get_blacklist():
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("SELECT ip_address, reason, timestamp, country, city, org FROM blocked_ips ORDER BY timestamp DESC")
    rows = cur.fetchall(); conn.close()
    return [{"ip": r[0], "reason": r[1], "timestamp": r[2], "country": r[3], "city": r[4], "org": r[5]} for r in rows]

@app.get("/api/observations")
async def get_observations():
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("SELECT ip_address, risk_score, hit_count, last_reason, country, city, org, last_seen FROM observed_ips ORDER BY risk_score DESC")
    rows = cur.fetchall(); cur.close(); conn.close()
    return [{"ip": r[0], "score": r[1], "hits": r[2], "reason": r[3], "country": r[4], "city": r[5], "org": r[6], "last_seen": r[7]} for r in rows]

@app.delete("/api/blacklist/{ip}")
async def remove_from_blacklist(ip: str):
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit(); conn.close()
    return {"status": "success"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)