from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings

CHROMA_DIR = '../data/chroma_db'
COLLECTION = 'soc_knowledge'

_retriever = None  # singleton

def get_retriever():
    global _retriever
    if _retriever is not None:
        return _retriever

    embeddings = HuggingFaceEmbeddings(
        model_name='sentence-transformers/all-MiniLM-L6-v2',
        model_kwargs={'device': 'cpu'}
    )
    vectorstore = Chroma(
        persist_directory=CHROMA_DIR,
        collection_name=COLLECTION,
        embedding_function=embeddings,
    )
    _retriever = vectorstore.as_retriever(
        search_type='similarity',
        search_kwargs={'k': 4}   # top-4 most similar chunks
    )
    return _retriever
