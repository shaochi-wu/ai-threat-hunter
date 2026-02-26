import streamlit as st
import os
import time
import ast
import asyncio
import nest_asyncio  # <--- 關鍵武器 1
from contextlib import AsyncExitStack

from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_text_splitters import CharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.tools import tool
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.messages import HumanMessage, AIMessage

from langgraph.graph import StateGraph, MessagesState, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_core.messages import SystemMessage

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.sse import sse_client 
from langchain_core.tools import tool

nest_asyncio.apply()
st.set_page_config(page_title="AI Threat Hunter", page_icon="🛡️", layout="wide")

# 側邊欄設定 (API Key 輸入與系統狀態)
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    st.title("Threat Hunter AI")
    st.markdown("---")
    
    # 優先從環境變數讀取 Key，如果沒有則讓使用者輸入
    load_dotenv()
    env_key = os.getenv("GOOGLE_API_KEY")
    api_key = st.text_input("輸入 Gemini API Key", value=env_key if env_key else "", type="password")
    
    st.markdown("### 系統狀態")
    if api_key:
        st.success("API Key 已載入")
    else:
        st.error("請輸入 API Key")

    st.markdown("---")
    st.markdown("### 功能說明")
    st.markdown("- 🔍 **RAG 知識庫**: 內建資安 SOP")
    st.markdown("- 🛠️ **IP 掃描**: 模擬檢查惡意 IP")
    st.markdown("- 🤖 **Agent**: 自主決策與分析")

# 如果沒有 Key，停止執行
if not api_key:
    st.info("請在左側輸入您的 Google API Key 以啟動系統")
    st.stop()

os.environ["GOOGLE_API_KEY"] = api_key

# ==========================================
# 建立模擬知識庫 (RAG System)
# ==========================================
@st.cache_resource # 使用快取，避免每次重新整理都要重跑
def init_rag_system():
    # 模擬公司內部的資安標準作業程序 (SOP)
    sop_data = """
    【資安事件等級定義】
    - Critical (嚴重): 涉及核心資料庫外洩、勒索病毒感染。需立即斷網並通報 CISO。
    - High (高): 偵測到外部惡意 IP 的持續掃描或暴力破解嘗試。需封鎖 IP。
    - Medium (中): 員工電腦偵測到潛在惡意軟體，已被防毒軟體隔離。
    - Low (低): 一般廣告軟體或非關鍵系統的異常登入。

    【IP 封鎖標準作業程序 (SOP)】
    1. 確認該 IP 在過去 24 小時內的連線次數。
    2. 使用 Threat Intelligence 工具查詢該 IP 信譽分數。
    3. 若信譽分數 < 50 或涉及已知的僵屍網路，立即在防火牆進行封鎖。
    4. 記錄事件並產出報告。

    【Log 分析指南】
    - 若 Log 中出現 'Failed password' 超過 5 次，視為暴力破解。
    - 若出現 'UNION SELECT' 等關鍵字，視為 SQL Injection 攻擊。
    """
    
    text_splitter = CharacterTextSplitter(chunk_size=200, chunk_overlap=20)
    docs = text_splitter.create_documents([sop_data])
    
    # 使用 HuggingFace 免費模型建立向量庫
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vector_db = FAISS.from_documents(docs, embeddings)
    return vector_db.as_retriever()

retriever = init_rag_system()

# 這是我們用來連接 Server 的通用函式
async def _call_mcp_tool(tool_name: str, arguments: dict):
    # 連接到本地的 server.py (預設跑在 8000 port)
    url = "http://localhost:8000/sse"
    
    async with AsyncExitStack() as stack:
        # 建立 SSE 連線
        try:
            client = await stack.enter_async_context(sse_client(url))
            session = await stack.enter_async_context(ClientSession(client[0], client[1]))
            await session.initialize()
            
            # 呼叫遠端工具
            result = await session.call_tool(tool_name, arguments)
            
            # 回傳結果 (MCP 回傳的是一個 List[TextContent])
            return result.content[0].text
        except Exception as e:
            return f"MCP 連線錯誤 (請確認 server.py 有在執行): {str(e)}"

# ==========================================
# 定義 Agent 的工具 (Tools)
# ==========================================
@tool
def check_ip_intelligence(ip_address: str):
    """
    [MCP Tool] 綜合查詢 IP 威脅情資。
    這會透過 MCP 協定連接到外部 Server，同時查詢「真實地理位置」與「內部黑名單」。
    """
    # 使用 asyncio.run 來執行上面的非同步連線
    # 因為有了 nest_asyncio.apply()，這裡不會報錯
    
    # 1. 查真實地理位置
    geo_info = asyncio.run(_call_mcp_tool("lookup_ip_geolocation", {"ip": ip_address}))
    
    # 2. 查內部資料庫
    db_info = asyncio.run(_call_mcp_tool("query_internal_db", {"ip": ip_address}))
    
    return f"{geo_info}\n\n{db_info}"
# def check_ip_reputation(ip_address: str):
#     """
#     查詢特定 IP 位址的信譽分數與地理位置。
#     當使用者提供 IP 位址並詢問其安全性時使用此工具。
#     """
#     # 模擬外部 API 的回傳結果
#     time.sleep(1) # 假裝在連線
#     if ip_address.startswith("192.168"):
#         return {"ip": ip_address, "risk_level": "Safe", "location": "Local Network", "score": 95}
#     elif ip_address == "8.8.8.8":
#         return {"ip": ip_address, "risk_level": "Safe", "location": "US (Google)", "score": 99}
#     elif ip_address == "1.2.3.4":
#         return {"ip": ip_address, "risk_level": "Critical", "location": "Unknown", "score": 10, "threat": "Botnet Activity"}
#     else:
#         return {"ip": ip_address, "risk_level": "Medium", "location": "China", "score": 45, "note": "Suspicious traffic detected"}

@tool
def search_security_sop(query: str):
    """
    查詢內部資安 SOP 文件
    當需要知道公司規定、定義等級或處理流程時使用此工具
    """
    docs = retriever.invoke(query)
    return "\n\n".join([doc.page_content for doc in docs])

tools = [check_ip_intelligence, search_security_sop]

# ==========================================
# 初始化 AI Agent
# ==========================================
llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)

# prompt = ChatPromptTemplate.from_messages([
#     ("system", """你是一個專業的資安分析師 (SOC Analyst) Agent。
#     你的任務是協助使用者分析資安威脅。
    
#     請遵循以下步驟：
#     1. 根據使用者的問題，判斷是否需要查詢 IP 信譽或公司 SOP。
#     2. 若發現高風險威脅，請引用 SOP 中的處理流程給出建議。
#     3. 回答請保持專業、簡潔，並使用 Markdown 格式（可以使用表格整理數據）。
#     """),
#     ("placeholder", "{chat_history}"),
#     ("human", "{input}"),
#     ("placeholder", "{agent_scratchpad}"),
# ])

# agent = create_tool_calling_agent(llm, tools, prompt)
# agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# 1. 定義 System Prompt (系統提示詞)
# LangGraph 通常直接把 System Message 放在對話最前面，而不是用 PromptTemplate
sys_msg = SystemMessage(content="""你是一個專業的資安分析師 (SOC Analyst) Agent。
你的任務是協助使用者分析資安威脅。

請遵循以下步驟：
1. 根據使用者的問題，判斷是否需要查詢 IP 信譽或公司 SOP。
2. 若發現高風險威脅，請引用 SOP 中的處理流程給出建議。
3. 回答請保持專業、簡潔，並使用 Markdown 格式（可以使用表格整理數據）。
""")

# 2. 定義節點 (Nodes)
def agent_node(state: MessagesState):
    print("--- 進入 Agent 思考節點 ---")  # <--- 加入這行來除錯
    llm_with_tools = llm.bind_tools(tools)
    result = llm_with_tools.invoke([sys_msg] + state["messages"])
    
    # 如果有呼叫工具，印出來看看
    if result.tool_calls:
        print(f"--- Agent 決定呼叫工具: {result.tool_calls} ---")
        
    return {"messages": [result]}

# 3. 建立 Graph (流程圖)
builder = StateGraph(MessagesState)

# 加入節點
builder.add_node("agent", agent_node)
builder.add_node("tools", ToolNode(tools)) # LangGraph 內建的工具執行節點

# 定義邊 (Edges) - 決定流程怎麼跑
builder.add_edge(START, "agent")
# conditional_edges: 判斷 Agent 是要「繼續使用工具」還是「結束回答」
builder.add_conditional_edges("agent", tools_condition) 
builder.add_edge("tools", "agent") # 工具用完後，回傳給 Agent 繼續思考

# 編譯成可執行的 App
graph = builder.compile()

# ==========================================
# Streamlit 聊天介面邏輯
# ==========================================

# 初始化聊天紀錄
if "messages" not in st.session_state:
    st.session_state.messages = []

# 顯示歷史訊息
for msg in st.session_state.messages:
    role = "user" if isinstance(msg, HumanMessage) else "assistant"
    with st.chat_message(role):
        st.markdown(msg.content)

# 處理使用者輸入
if user_input := st.chat_input("請輸入指令 (例如: 分析 IP 1.2.3.4 的風險)"):
    # 1. 顯示使用者訊息
    st.session_state.messages.append(HumanMessage(content=user_input))
    with st.chat_message("user"):
        st.markdown(user_input)

    # 2. Agent 思考與回應
    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        message_placeholder.markdown("🤖 AI 正在分析威脅情報與 SOP...")
            
        try:
            # 呼叫 Agent (要把 chat_history 截斷)
            # response = agent_executor.invoke({
            #     "input": user_input,
            #     "chat_history": st.session_state.messages[:-1]
            # })
            
            # raw_output = response["output"]
            
            def parse_gemini_output(content):
                # 1. 如果是純字串，先嘗試用 AST 把它還原成 List/Dict
                if isinstance(content, str):
                    # 如果看起來像 List 或 Dict，才去解析
                    if content.strip().startswith("[") or content.strip().startswith("{"):
                        try:
                            # 把 "[{'...'}, '...']" 字串變成真正的 Python List
                            content = ast.literal_eval(content)
                        except:
                            pass # 解析失敗就當作普通字串處理

                # 2. 如果是 List (無論是原本就是，還是剛解析出來的)
                if isinstance(content, list):
                    final_text = ""
                    for item in content:
                        if isinstance(item, dict):
                            # 如果是字典，抓 text 欄位
                            final_text += item.get('text', '')
                        elif isinstance(item, str):
                            # 如果是字串，直接接上去
                            final_text += item
                    return final_text
                
                # 3. 如果都不是，就是單純的 String
                return str(content)
            
            # LangGraph 的輸入：直接給目前的對話紀錄 (messages)
            # st.session_state.messages 已經包含了 HumanMessage
            inputs = {"messages": st.session_state.messages}
            
            # 使用 stream 來獲取即時回應 (這裡用 invoke 比較簡單示範，但 stream 體驗更好)
            # 這裡我們取最後一個狀態的訊息
            result = graph.invoke(inputs)
            
            # 從結果中取出最後一條 AI 的回應
            last_message = result["messages"][-1]
            raw_content = last_message.content
            
            # 使用解析函式清洗輸出的內容 
            clean_content = parse_gemini_output(raw_content)
            
            # 顯示清洗後的結果
            message_placeholder.markdown(clean_content)
            
            # 儲存到 session_state (記得存清洗過的版本，避免下次歷史紀錄讀進來又壞掉)
            st.session_state.messages.append(AIMessage(content=clean_content))

        except Exception as e:
            message_placeholder.error(f"發生錯誤: {str(e)}")
            # 建議印出詳細錯誤以便除錯
            import traceback
            traceback.print_exc()

            # 執行解析
        #     result_text = parse_gemini_output(raw_output)
            
        #     # ---------------------------------------

        #     # 顯示結果
        #     message_placeholder.markdown(result_text)
        #     st.session_state.messages.append(AIMessage(content=result_text))
            
        # except Exception as e:
        #     message_placeholder.error(f"發生錯誤: {str(e)}")
        #     print(f"DEBUG Error: {e}")