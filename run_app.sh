#!/bin/bash

# 패키지 설치
# pip install -r requirements.txt
pip install streamlit
pip install pyyaml
pip install azure-storage-blob
pip install azure-identity
pip install azure-search-documents
pip install openai
pip install requests
pip install python-dotenv

# Streamlit 앱 실행
python -m streamlit run app.py --server.port 8000 --server.address 0.0.0.0
