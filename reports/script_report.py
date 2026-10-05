import html
import os
import sys
from datetime import datetime, timedelta

import requests

# configurações do relatório
PRODUCT = "Red Hat OpenShift GitOps"
VERSION = "1.21"
DAYS_BACK = 50

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

def product_filter_candidates(product: str, version: str) -> list:
    """
    Variantes do filtro de produto, testadas em ordem até alguma retornar dados.
    """
    esc = escape_solr(product)
    return [
        ("produto|*|versão|*", f"portal_product_filter:{esc}|*|{version}|*"),
        ("produto|*|versão|", f"portal_product_filter:{esc}|*|{version}|"),
        ("nome do produto + versão na synopsis",
         f'portal_product_names:"{product}" AND portal_synopsis:"{version}"'),
    ]

def parse_date(value):
    """Converte '2026-05-12T00:00:00Z' em datetime (ou None se inválido)."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d")
    except ValueError:
        return None

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

def fetch_all(session: requests.Session, product_fq: str, cutoff: datetime) -> list:
    """Pagina os resultados até cobrir o período (ordenado por update date desc)."""
    docs_all = []
    start = 0
    for _ in range(MAX_PAGES):
        data = request_page(session, product_fq, start)
        response = data.get("response", {})
        docs = response.get("docs", [])
        total = response.get("numFound", 0)
        print(f"[INFO] numFound={total} | página com {len(docs)} documento(s)")
        if not docs:
            break
        docs_all.extend(docs)
        start += len(docs)
        if start >= total:
            break
        # publication <= update: se o último update já é anterior ao corte, pode parar
        last_update = parse_date(docs[-1].get("portal_update_date"))
        if last_update and last_update < cutoff:
            break
    return docs_all

def fetch_errata(product: str, version: str, cutoff: datetime) -> list:
    """Tenta cada variante de filtro até obter resultados."""
    with requests.Session() as session:
        for label, product_fq in product_filter_candidates(product, version):
            print(f"[INFO] Tentando filtro: {label}")
            docs = fetch_all(session, product_fq, cutoff)
            if docs:
                print(f"[INFO] Filtro '{label}' retornou {len(docs)} errata(s).")
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
            f"Nenhuma errata publicada nos últimos {DAYS_BACK} dias</td></tr>"
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

def build_html(errata: list, start: datetime, end: datetime, generated_at: datetime) -> str:
    types = ", ".join(ADVISORY_TYPES) if ADVISORY_TYPES else "Todos"
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
  <div class="meta"><strong>Produto:</strong> {html.escape(PRODUCT)} &nbsp;|&nbsp; 
  <strong>Versão:</strong> {html.escape(VERSION)}</div>
  <div class="meta"><strong>Período analisado:</strong> {start.strftime('%d/%m/%Y')} a {end.strftime('%d/%m/%Y')} &nbsp;|&nbsp; 
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
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    cutoff = today - timedelta(days=DAYS_BACK)

    print(f"[INFO] Produto: {PRODUCT} | Versão: {VERSION}")
    print(f"[INFO] Período: {cutoff.strftime('%d/%m/%Y')} a {today.strftime('%d/%m/%Y')}")

    docs = fetch_errata(PRODUCT, VERSION, cutoff)
    errata = filter_errata(docs, cutoff)
    print(f"[INFO] {len(errata)} errata(s) no período analisado.")

    path = save_report(build_html(errata, cutoff, today, now), now)
    print(f"[OK] Relatório salvo em: {path}")

if __name__ == "__main__":
    main()