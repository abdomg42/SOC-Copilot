# agent/scripts/build_kb.py
import json, requests, os, yaml
from pathlib import Path
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

DATA       = Path('../data')
CHROMA_DIR = Path('../data/chroma_db')
COLLECTION = 'soc_knowledge'

# ── Embedding model (local, no API key needed) ──────────────────────
EMBEDDINGS = HuggingFaceEmbeddings(
    model_name='sentence-transformers/all-MiniLM-L6-v2',
    model_kwargs={'device': 'cpu'}
)

# ── 1. MITRE ATT&CK ─────────────────────────────────────────────────
def load_mitre() -> list:
    path = DATA / 'mitre_attack.json'
    print(path)
    if not path.exists():
        print('Downloading MITRE ATT&CK (~30MB)...')
        r = requests.get(
            'https://raw.githubusercontent.com/mitre/cti/master'
            '/enterprise-attack/enterprise-attack.json', timeout=60
        )
        path.write_bytes(r.content)
    data = json.loads(path.read_text())
    docs = []
    for obj in data['objects']:
        if obj.get('type') == 'attack-pattern' and not obj.get('revoked'):
            refs = obj.get('external_references', [])
            tid  = next((e['external_id'] for e in refs
                         if e.get('source_name') == 'mitre-attack'), '')
            content = (
                f'Technique {tid}: {obj["name"]}\n'
                f'{obj.get("description", "")}\n'
                f'Platforms: {", ".join(obj.get("x_mitre_platforms", []))}\n'
                f'Permissions: {", ".join(obj.get("x_mitre_permissions_required", []))}' 
            )
            docs.append(Document(
                page_content=content,
                metadata={'source': 'mitre', 'technique_id': tid, 'name': obj['name']}
            ))
    print(f'MITRE: {len(docs)} techniques loaded')
    return docs

# ── 2. NVD CVEs ─────────────────────────────────────────────────────
def load_nvd() -> list:
    docs = []
    for kw in ['openssh', 'linux kernel', 'sudo', 'apache2']:
        url = (f'https://services.nvd.nist.gov/rest/json/cves/2.0'
               f'?keywordSearch={kw}&resultsPerPage=50')
        try:
            r = requests.get(url, timeout=30)
            if r.status_code != 200: continue
            for item in r.json().get('vulnerabilities', []):
                cve  = item['cve']
                desc = cve['descriptions'][0]['value']
                cid  = cve['id']
                score = (cve.get('metrics', {})
                             .get('cvssMetricV31', [{}])[0]
                             .get('cvssData', {})
                             .get('baseScore', 'N/A'))
                docs.append(Document(
                    page_content=f'{cid} (CVSS {score}): {desc}',
                    metadata={'source': 'nvd', 'cve_id': cid}
                ))
        except Exception as e:
            print(f'NVD error for {kw}: {e}')
    print(f'NVD: {len(docs)} CVEs loaded')
    return docs

# ── 3. Runbooks (local Markdown files) ──────────────────────────────
def load_runbooks() -> list:
    docs = []
    runbooks_dir = DATA / 'runbooks'
    runbooks_dir.mkdir(exist_ok=True)
    for f in runbooks_dir.glob('*.md'):
        docs.append(Document(
            page_content=f.read_text(encoding='utf-8'),
            metadata={'source': 'runbook', 'filename': f.name}
        ))
    print(f'Runbooks: {len(docs)} files loaded')
    return docs

# ── 4. Sigma Rules ──────────────────────────────────────────────────
def load_sigma() -> list:
    sigma_dir = DATA / 'sigma_rules'
    if not sigma_dir.exists():
        print('Cloning Sigma rules (shallow, ~2min)...')
        os.system(
            f'git clone --depth 1 https://github.com/SigmaHQ/sigma {sigma_dir}'
        )
    docs = []
    for f in list((sigma_dir / 'rules/linux').rglob('*.yml'))[:80]:
        try:
            rule = yaml.safe_load(f.read_text())
            if rule and rule.get('title'):
                content = (
                    f'Sigma Rule: {rule["title"]}\n'
                    f'{rule.get("description", "")}\n'
                    f'Tags: {", ".join(rule.get("tags", []))}'
                )
                docs.append(Document(
                    page_content=content[:800],
                    metadata={'source': 'sigma', 'title': rule['title']}
                ))
        except Exception:
            pass
    print(f'Sigma: {len(docs)} rules loaded')
    return docs

# ── BUILD VECTOR STORE ───────────────────────────────────────────────
def build():
    all_docs = load_mitre() + load_nvd() + load_runbooks() + load_sigma()
    print(f'Total documents: {len(all_docs)}')

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=600,
        chunk_overlap=80,
        separators=['\n\n', '\n', '. ', ' ', '']
    )
    chunks = splitter.split_documents(all_docs)
    print(f'Total chunks: {len(chunks)} → building ChromaDB...')

    vectorstore = Chroma.from_documents(
        documents=chunks,
        embedding=EMBEDDINGS,
        collection_name=COLLECTION,
        persist_directory=str(CHROMA_DIR)
    )
    print(f'ChromaDB saved → {CHROMA_DIR}')
    print(f'Collection size: {vectorstore._collection.count()} chunks')

if __name__ == '__main__':
    build()
