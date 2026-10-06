import html
import re 
import os
import sys
from datetime import datetime
import requests

# configurações do relatório
PRODUCT = "DevWorkspace Operator"
VERSION = "0.36"
# DAYS_BACK = 120
LAST_VERSION = "0.40" # última versão atualizada que ainda será incluída no relatório (para histórico)

# Tipos de advisory que serão incluídos no relatório. Se vazio, inclui todos.
ADVISORY_TYPES = ["Bug Fix Advisory", "Security Advisory", "Product Enhancement Advisory"]

# configurações da API para consulta de erratas 
API_URL = "https://access.redhat.com/hydra/rest/search/kcs"
ERRATA_URL = "https://access.redhat.com/errata/{id}"
OUTPUT_DIR = "generated_reports"
ROWS = 200
MAX_PAGES = 10
TIMEOUT = 30
FIELDS = (
    "id,portal_severity,portal_advisory_type,portal_product_names,"
    "portal_publication_date,portal_update_date,portal_synopsis"
)


def escape_solr(value: str) -> str:
    """Escapa espaços para o Solr (' ' -> '\\ ')."""
    return value.replace(" ", "\\ ")

def product_filter_candidates(product: str) -> list:
    """
    filtra por produto, testadas em ordem até alguma retornar dados.
    """
    esc = escape_solr(product)
    return [
        ("produto genérico", f"portal_product_filter:{esc}|*"),
        ("nome do produto", f'portal_product_names:"{product}"'),
    ]

def parse_date(value):
    """Converte '2026-05-12T00:00:00Z' em datetime (ou None se inválido)."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d")
    except ValueError:
        return None

def parse_version_tuple(v_str: str) -> tuple:
    """
    convrte string em tupla para comparação.
    """
    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', str(v_str))
    if match:
        return tuple(map(int, match.group(1).split('.')))
    return (0,)

def request_page(session: requests.Session, product_fq: str, start: int) -> dict:
    """Faz uma requisição paginada. Em erro, mostra a URL tentada e encerra."""
    params = {
        "q": "*:*",
        "rows": ROWS,
        "start": start,
        "sort": "portal_update_date desc",
        "fq": ['documentKind:("Errata")', product_fq],
        "fl": FIELDS,
        "wt": "json",
    }
    headers = {"Accept": "application/json", "User-Agent": "errata-report/1.0"}
    prepared = requests.Request("GET", API_URL, params=params, headers=headers).prepare()
    print(f"[INFO] Consultando API: {prepared.url}")

    try:
        response = session.send(prepared, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.HTTPError as exc:
        print(f"[ERRO] A API retornou erro HTTP {exc.response.status_code}.")
    except requests.RequestException as exc:
        print(f"[ERRO] Falha na requisição: {exc}")
    except ValueError:
        print("[ERRO] A resposta da API não é um JSON válido.")
    print(f"[ERRO] URL tentada: {prepared.url}")
    sys.exit(1)

def fetch_all(session: requests.Session, product_fq: str) -> list:
    """Pagina os resultados até cobrir o período (ordenado por update date desc)."""
    docs_all = []
    start = 0
    for _ in range(MAX_PAGES):
        data = request_page(session, product_fq, start)
        response = data.get("response", {})
        docs = response.get("docs", [])
        total = response.get("numFound", 0)
        print(f"[INFO] Página com {len(docs)} documento(s)")
        if not docs:
            break
        docs_all.extend(docs)
        start += len(docs)
        if start >= total:
            break

    return docs_all

def fetch_errata(product: str) -> list:
    '''Busca erratas para o produto, testando filtros em ordem até algum retornar resultados.'''
    with requests.Session() as session:
        for label, product_fq in product_filter_candidates(product):
            print(f"[INFO] Tentando filtro: {label}")
            docs = fetch_all(session, product_fq)
            if docs:
                print(f"[INFO] Filtro '{label}' retornou {len(docs)} errata(s) brutas.")
                return docs
            print(f"[AVISO] Filtro '{label}' retornou 0 resultados.")
    return []

# ================= TRATAMENTO DOS DADOS ========================
def as_text(value) -> str:
    """Normaliza campos que podem vir como lista ou string."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)

def filter_errata(docs: list, cutoff: datetime) -> list:
    """Filtra por data de publicação e tipo de advisory; ordena do mais recente."""
    wanted = {t.lower() for t in ADVISORY_TYPES}
    result = []
    for doc in docs:
        pub_date = parse_date(doc.get("portal_publication_date"))
        if not pub_date or pub_date < cutoff:
            continue
        if wanted and as_text(doc.get("portal_advisory_type")).lower() not in wanted:
            continue
        doc["_pub_date"] = pub_date
        doc["_upd_date"] = parse_date(doc.get("portal_update_date")) or pub_date
        result.append(doc)
    result.sort(key=lambda d: (d["_pub_date"], d["_upd_date"]), reverse=True)
    return result

def filter_errata_version(docs: list, v_min: str, v_max: str) -> list:
    """
    Avalia se a errata pertence ao intervalo desejado. 
    """
    min_tuple = parse_version_tuple(v_min)
    max_tuple = parse_version_tuple(v_max)
    wanted = {t.lower() for t in ADVISORY_TYPES}
    result = []
    
    for doc in docs:
        # A Red Hat quase sempre coloca a versão afetada na sinopse (título) do documento
        texto_busca = f"{doc.get('portal_synopsis', '')} {doc.get('portal_product_names', '')}"
        doc_v_tuple = parse_version_tuple(texto_busca)
        
        # Ignora se não conseguiu achar um número de versão no documento
        if doc_v_tuple == (0,):
            continue
            
        # Verifica se a versão do documento está >= VERSION e <= LAST_VERSION
        if min_tuple <= doc_v_tuple <= max_tuple:
            if wanted and as_text(doc.get("portal_advisory_type")).lower() not in wanted:
                continue
            
            pub_date = parse_date(doc.get("portal_publication_date")) # data de publicação da errata
            doc["_pub_date"] = pub_date or datetime.min
            doc["_upd_date"] = parse_date(doc.get("portal_update_date")) or doc["_pub_date"]
            result.append(doc)
            
    # Ordena as erratas filtradas da mais nova para a mais velha
    result.sort(key=lambda d: (d["_pub_date"], d["_upd_date"]), reverse=True)
    return result


# ==================== GERAÇÃO DO HTML ==========================
def severity_class(severity: str) -> str:
    sev = (severity or "").strip().lower()
    if sev in ("important", "critical"):
        return "sev-high"
    if sev == "moderate":
        return "sev-moderate"
    if sev == "low":
        return "sev-low"
    return "sev-none"

CSS = """
body { font-family: 'Open Sans', Arial, sans-serif; background: #fff; color: #333; margin: 0; padding: 32px; }
header { border-bottom: 2px solid #d2d2d2; margin-bottom: 24px; padding-bottom: 12px; }
h1 { font-size: 24px; margin: 0 0 8px; color: #151515; }
.meta { font-size: 14px; color: #555; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th { text-align: left; padding: 12px; border-bottom: 2px solid #d2d2d2; white-space: nowrap; }
td { padding: 12px; border-bottom: 1px solid #e6e6e6; vertical-align: top; }
td.adv { white-space: nowrap; font-weight: 600; }
tr:hover td { background: #fafafa; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.sev-high { background: #c9190b; color: #fff; }
.sev-moderate { background: #ec7a08; color: #fff; }
.sev-low { background: #f0ab00; color: #fff; }
.sev-none { background: #e0e0e0; color: #444; border: 1px solid #c7c7c7; }
.empty { text-align: center; padding: 32px; color: #666; }
footer { margin-top: 24px; font-size: 12px; color: #888; }
"""

def build_rows(errata: list) -> str:
    if not errata:
        return (
            f'<tr><td colspan="7" class="empty">'
            f"Nenhuma errata publicada entre as versões v{VERSION} e v{LAST_VERSION}</td></tr>"
        )
    rows = []
    for doc in errata:
        errata_id = as_text(doc.get("id"))
        severity = as_text(doc.get("portal_severity")) or "None"
        rows.append(
            "<tr>"
            f'<td class="adv"><a href="{html.escape(ERRATA_URL.format(id=errata_id))}" '
            f'target="_blank" rel="noopener">{html.escape(errata_id)}</a></td>'
            f"<td>{html.escape(as_text(doc.get('portal_synopsis')))}</td>"
            f"<td>{html.escape(as_text(doc.get('portal_advisory_type')))}</td>"
            f'<td><span class="badge {severity_class(severity)}">{html.escape(severity)}</span></td>'
            f"<td>{html.escape(as_text(doc.get('portal_product_names')))}</td>"
            f"<td>{doc['_pub_date'].strftime('%d/%m/%Y')}</td>"
            f"<td>{doc['_upd_date'].strftime('%d/%m/%Y')}</td>"
            "</tr>"
        )
    return "\n".join(rows)

def build_html(errata: list, generated_at: datetime) -> str:
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Relatório de Erratas - {html.escape(PRODUCT)} {html.escape(VERSION)}</title>
<link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600;700&display=swap" rel="stylesheet">
<style>{CSS}</style>
</head>
<body>
<header>
  <h1>Relatório de Erratas</h1>
  <div class="meta"><strong>Produto:</strong> {html.escape(PRODUCT)}; 
  <div class="meta"><strong>Periodo de versões analisadas:</strong> v{VERSION} a v{LAST_VERSION} &nbsp;|&nbsp; 
  <strong>Total:</strong> {len(errata)}</div>
</header>
<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>Advisory</th><th>Synopsis</th><th>Advisory Type</th><th>Severity</th>
      <th>Products</th><th>Issued Date</th><th>Updated Date</th>
    </tr>
  </thead>
  <tbody>
{build_rows(errata)}
  </tbody>
</table>
</div>
<footer>Gerado em {generated_at.strftime('%d/%m/%Y %H:%M')}.</footer>
</body>
</html>
"""

def save_report(content: str, generated_at: datetime) -> str:
    """Salva o relatório em arquivo HTML e retorna o caminho do arquivo."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"Report_Erratas_{generated_at.strftime('%Y%m%d_%H%M')}.html"
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ==================== FUNÇÃO PRINCIPAL =========================
def main():
    now = datetime.now()
    print (f"[INFO] Iniciando relatório de erratas para {PRODUCT} entre versões {VERSION} e {LAST_VERSION}.")
    print(f"[INFO] Versão atual: {VERSION} | Última versão atualizada: {LAST_VERSION}")

    docs_brutos = fetch_errata(PRODUCT)

    errata = filter_errata_version(docs_brutos, VERSION, LAST_VERSION)
    print(f"[INFO] {len(errata)} errata(s) encontradas neste intervalo de versões.")

    path = save_report(build_html(errata, now), now)
    
    print(f"[OK] Relatório salvo em: {path}")

if __name__ == "__main__":
    main()
