from typing import Optional
import json
from pathlib import Path
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

CHROMA_DIR = Path('../data/chroma_db')


def chroma_db_retiever():
    embedding = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    vectorstore = Chroma(persist_directory=str(CHROMA_DIR), collection_name="soc_copilot", embedding_function=embedding)
    return vectorstore.as_retriever(search_kwargs={"k": 5})