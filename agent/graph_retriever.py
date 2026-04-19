from typing import Optional
import json
from pathlib import Path
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from graph_db import get_driver

CHROMA_DIR = Path('../data/chroma_db')


def chroma_db_retiever():
    embedding = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
    vectorstore = Chroma(persist_directory=str(CHROMA_DIR), collection_name="soc_copilot", embedding_function=embedding)
    return vectorstore.as_retriever(search_kwargs={"k": 5})

_chroma = None
def retriever():
    global _chroma
    if _chroma is None: _chroma = chroma_db_retiever()
    return _chroma


# get ip context from neo4j 
def get_ip_context(ip):
    try : 
        with get_driver().session() as s :
            summary = s.run("""
                MATCH (ip:IP {address: $ip})
                RETURN ip.risk_score AS risk, ip.attack_count AS count,
                       ip.first_seen AS first, ip.last_seen AS last
            """, ip=ip).single()
            techs = s.run("""
                MATCH (ip:IP {address:$ip})-[:TRIGGERED]->(:Alert)
                      -[:USES]->(t:MitreTechnique)
                RETURN DISTINCT t.tid AS tid, t.name AS name
            """, ip=ip).data()
            chain = s.run("""
                MATCH path=(ip:IP {address:$ip})-[:TRIGGERED]->(a1:Alert)
                           -[:FOLLOWED_BY*1..4]->(a2:Alert)
                RETURN [n IN nodes(path) WHERE n:Alert |
                        {desc:n.description, sev:n.severity}] AS chain
                ORDER BY length(path) DESC LIMIT 1
            """, ip=ip).single()
        return {
            'known':         bool(summary and summary['count'] > 0),
            'risk_score':    summary['risk'] if summary else 0.0,
            'attack_count':  summary['count'] if summary else 0,
            'first_seen':    summary['first'] if summary else None,
            'techniques':    techs,
            'kill_chain':    chain['chain'] if chain else [],
        }
    except Exception as e:
        print(f'graph_retriever Neo4j IP context error: {e}')
        return {'known': False, 'risk_score': 0.0, 'attack_count': 0,
                'techniques': [], 'kill_chain': []}

# get D3FEND defenses for detected MITRE techniques 
def get_d3fend_for_techniques(mitre_ids):
    try:
        with get_driver().session() as s:
            result = s.run("""
                UNWIND $ids AS tid
                MATCH (d:D3fendTechnique)-[:DEFENDS_AGAINST]
                      ->(t:MitreTechnique {tid: tid})
                RETURN DISTINCT d.name AS defense,
                               t.tid   AS attack_technique
            """, ids=mitre_ids)
            return result.data()
    except Exception as e:
        print(f'[graph_retriever] D3FEND query error: {e}')
        return []

