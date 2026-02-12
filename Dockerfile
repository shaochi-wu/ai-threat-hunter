# 1. 指定 Python 環境 (基底)
FROM python:3.10-slim

# 2. 設定容器內的工作目錄
WORKDIR /app

# 3. 複製需求清單進去
COPY requirements.txt .

# 4. 安裝套件 (這裡會依照 requirements.txt 下載)
RUN pip install --no-cache-dir -r requirements.txt

# 5. 複製所有程式碼進去
COPY . .

# 6. 開放 8501 埠口 (Streamlit 用)
EXPOSE 8501

# 7. 設定啟動指令 (一定要加 server.address=0.0.0.0 才能被外面連到)
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]