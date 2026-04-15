from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

embedding = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

vs = Chroma(
    persist_directory="../data/chroma_db",
    collection_name="soc_knowledge",
    embedding_function=embedding
)

print(f"the length of documents in the collection: {vs._collection.count()}")
docs = vs.similarity_search("How to detect privilege escalation?", k=3)
print(f"Top {len(docs)} results for query: 'How to detect privilege escalation?'\n")
for d in docs:
    print(d.page_content)
    print("------")
    

