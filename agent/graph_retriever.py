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
        print(f'graph_retriever D3FEND query error: {e}')
        return []

# get traverse MITRE graph for related techniques 
def get_mitre_context(tid):
    try:
        with get_driver().session() as s:
            result = s.run("""
                MATCH (t:MitreTechnique {tid: $tid})
                OPTIONAL MATCH (t)-[:BELONGS_TO]->(tac:MitreTactic)
                OPTIONAL MATCH (t)-[:SUB_TECHNIQUE_OF]->(parent:MitreTechnique)
                OPTIONAL MATCH (sib)-[:SUB_TECHNIQUE_OF]->(parent)
                  WHERE sib.tid <> $tid
                RETURN t.name     AS name,
                       t.desc     AS desc,
                       t.platforms AS platforms,
                       collect(DISTINCT tac.name)  AS tactics,
                       parent.tid  AS parent_tid,
                       parent.name AS parent_name,
                       collect(DISTINCT sib.tid)   AS siblings
                LIMIT 1
            """, tid=tid).single()
            return dict(result) if result else {}
    except Exception as e:
        print(f'graph_retriever MITRE context error: {e}')
        return {}
# ChromaDB: semantic search 
def semantic_search(query):
    try:
        docs = retriever().invoke(query)
        return [{'text': d.page_content, 'source': d.metadata.get('source','?')}
                for d in docs]
    except Exception as e:
        print(f'[graph_retriever] ChromaDB error: {e}')
        return []

# Main Function : combining all retrieval resources for the llm prompt
def retrieve_all(alert):
    ip = alert.get('src_ip','')
    desc      = alert.get('rule_description', '')
    mitre_ids = alert.get('mitre_ids', [])
    category  = alert.get('ml_attack_category', '')
    ip_context = get_ip_context(ip)      # IP history from Neo4j
    d3fend = get_d3fend_for_techniques(mitre_ids)      # D3FEND defenses from Neo4j
    mitre_ctx = get_mitre_context(mitre_ids[0]) if mitre_ids else {}        # MITRE technique details from Neo4j
    query   = f'{desc} {category} {" ".join(mitre_ids)}'    
    rag_docs = semantic_search(query)       # Semantic search from ChromaDB
    return {
        'ip_context':  ip_context,       
        'd3fend':      d3fend,         
        'mitre_ctx':   mitre_ctx,      
        'rag_docs':    rag_docs,       
    }

# Build the LLM prompt : convirting the retrieve_all() output into clean prompt
def format_for_prompt(ctx):
    sections = []
    # IP history section
    ip = ctx.get('ip_context', {})
    if ip.get('known'):
        techs_str = ', '.join(t['tid'] for t in ip.get('techniques', []))
        chain = ip.get('kill_chain', [])
        ip_section = (
            f'KNOWN ATTACKER (risk={ip["risk_score"]:.2f},'
            f' attacks={ip["attack_count"]}, techniques={techs_str})'
        )
        if chain:
            steps = ' -> '.join(c.get('desc','?')[:30] for c in chain)
            ip_section += f'\nKILL CHAIN: {steps}'
    else:
        ip_section = 'First time this IP is seen in our environment.'
    sections.append(f'[IP HISTORY]\n{ip_section}')

    # MITRE context from graph
    mc = ctx.get('mitre_ctx', {})
    if mc.get('name'):
        mitre_section = (
            f'{mc["name"]} — tactics: {", ".join(mc.get("tactics", []))}\n'
            f'Platforms: {", ".join(mc.get("platforms", []))}\n'
            f'{mc.get("desc", "")[:200]}'
        )
        if mc.get('parent_name'):
            mitre_section += f'\nParent technique: {mc["parent_tid"]} {mc["parent_name"]}'
        sections.append(f'[MITRE TECHNIQUE DETAILS]\n{mitre_section}')

    # D3FEND defenses from graph
    d3 = ctx.get('d3fend', [])
    if d3:
        d3_lines = '\n'.join(
            f'  - {d["defense"]} (defends {d["attack_technique"]})'
            for d in d3[:5]
        )
        sections.append(f'[D3FEND DEFENSES FROM GRAPH]\n{d3_lines}')
    # RAG semantic passages
    rag = ctx.get('rag_docs', [])
    if rag:
        rag_lines = []
        for doc in rag[:4]:
            src = doc.get('source', '?').upper()
            txt = doc.get('text', '')[:250]
            rag_lines.append(f'  [{src}] {txt}')
        sections.append(f'[KNOWLEDGE BASE — CHROMADB]\n' + '\n'.join(rag_lines))

    return '\n\n'.join(sections)


