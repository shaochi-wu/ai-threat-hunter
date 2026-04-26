import os
import pickle
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import MarkdownTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_community.retrievers import BM25Retriever

# 確保輸出資料夾存在
os.makedirs("faiss_index", exist_ok=True)

print("1. 正在讀取知識庫文件...")
loader = TextLoader("knowledge_base/sop.md", encoding="utf-8")
documents = loader.load()

print("2. 正在進行文本切塊 (Chunking)...")
# 設定 chunk_size 為 500 字元，保留 80 字元的重疊(Overlap)以防上下文斷裂
text_splitter = MarkdownTextSplitter(chunk_size=500, chunk_overlap=80)
docs = text_splitter.split_documents(documents)

print(f"-> 共切分出 {len(docs)} 個文本塊。")

print("3. 建立 FAISS 向量索引 (負責：語意理解)...")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
vector_db = FAISS.from_documents(docs, embeddings)
vector_db.save_local("faiss_index")

print("4. 建立 BM25 關鍵字索引 (負責：精準名詞比對)...")
bm25_retriever = BM25Retriever.from_documents(docs)
# 將 BM25 序列化存成檔案，供 main.py 讀取
with open("faiss_index/bm25_index.pkl", "wb") as f:
    pickle.dump(bm25_retriever, f)

print("Hybrid 雙引擎知識庫建立完成！(已儲存至 faiss_index 資料夾)")