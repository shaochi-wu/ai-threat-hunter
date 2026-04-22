這是一個基於 **LangGraph** 與 **MCP (Model Context Protocol)** 架構開發的自動化資安威脅評估系統。本專案模擬企業級 SOC（資安營運中心）流程，結合 RAG 知識庫與實體防火牆封鎖邏輯，並透過 **Human-in-the-Loop (HITL)** 機制確保自動化執行的合規性。

## 架構

- **Agentic Workflow**: 使用 LangGraph 構建有狀態的循環圖，實作「規劃 -> 工具呼叫 -> 狀態檢查 -> 回報」的完整推理鏈。
- **HITL (Human-in-the-Loop)**: 針對封鎖 IP 等敏感操作，實作中斷機制與人類審批流程，確保 AI 決策可被稽核。
- **MCP 協議整合**: 採用 Model Context Protocol，將資安工具（Geo-IP 查詢、SQLite IP 資料庫、RAG 檢索）解耦為獨立的 Server，提升擴展性。
- **混合 RAG 系統**: 使用 FAISS 向量資料庫儲存企業資安 SOP，結合 Prompt Engineering 實作嚴格的知識綁定（Grounding），避免模型幻覺。
- **架構解耦設計**: 將 System Prompt 抽離至獨立 Markdown 檔案，實作配置與邏輯分離；支援多 LLM 切換（Groq / Gemini / Ollama）。
- **聊天視窗**: Vue 3 實作的前端介面，除了即時對話，更包含實時同步的防火牆黑名單監控與 CRUD 操作面板。

