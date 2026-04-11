from langchain_community.vectorstores import Chroma
from pathlib import Path

CHROMA_DIR = Path('./chroma_db')
print(CHROMA_DIR)
vs = Chroma(persist_directory=str(CHROMA_DIR), collection_name='soc_knowledge', embedding_function=None)
print(vs._collection.count())