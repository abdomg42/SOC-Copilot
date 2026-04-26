from functools import lru_cache
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from pathlib import Path

CHROMA_DIR = str(Path(__file__).resolve().parent.parent / 'data' / 'chroma_db')
COLLECTION = 'soc_knowledge'

@lru_cache(maxsize=1)
def get_retriever():
    embeddings = HuggingFaceEmbeddings(
        model_name='sentence-transformers/all-MiniLM-L6-v2',
        model_kwargs={'device': 'cpu'}
    )
    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        collection_name=COLLECTION,
        embedding_function=embeddings,
    )
    return vectorstore.as_retriever(
        search_type='similarity',
        search_kwargs={'k': 4}   # top-4 most similar chunks
    )


def warm_up_retriever() -> None:
    """Load the embedding model and Chroma index once during server startup."""
    get_retriever()
