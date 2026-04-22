import os
from langchain_community.document_loaders import TextLoader
# [面試亮點] 使用專為 Markdown 設計的切塊器，比原本的 CharacterTextSplitter 更精準
from langchain_text_splitters import MarkdownTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

# 確保輸出資料夾存在
os.makedirs("faiss_index", exist_ok=True)

print("1. 正在讀取知識庫文件...")
loader = TextLoader("knowledge_base/sop.md", encoding="utf-8")
documents = loader.load()

print("2. 正在進行文本切塊 (Chunking)...")
# 設定 chunk_size 為 200 字元，保留 30 字元的重疊(Overlap)以防上下文斷裂
text_splitter = MarkdownTextSplitter(chunk_size=200, chunk_overlap=30)
docs = text_splitter.split_documents(documents)

print(f"-> 共切分出 {len(docs)} 個文本塊。")

print("3. 正在計算 Embedding 並建立向量資料庫 (FAISS)...")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
vector_db = FAISS.from_documents(docs, embeddings)

print("4. 正在將向量資料庫持久化儲存到本地端...")
# 將向量資料庫存成實體檔案
vector_db.save_local("faiss_index")
print("✅ 知識庫建立完成！(已儲存至 faiss_index 資料夾)")