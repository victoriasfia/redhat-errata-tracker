import os
import sys
import yaml
from datetime import datetime, timezone
import requests
from jinja2 import Environment, FileSystemLoader

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
YAML_FILE = os.path.join(PROJECT_ROOT, "yaml", "products.yaml")
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "template")
TEMPLATE_FILE = "report_template.html"
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "generated_reports")

# Tratamento para produtos com 'date: null'
DEFAULT_START_DATE = None

# Tipos de advisory que serão incluídos no relatório. Se vazio, inclui todos.
ADVISORY_TYPES = ["Bug Fix Advisory", "Security Advisory", "Product Enhancement Advisory"]

# Configurações da API
API_URL = "https://access.redhat.com/hydra/rest/search/kcs"
ERRATA_URL = "https://access.redhat.com/errata/{id}"
ROWS = 200
MAX_PAGES = 10
TIMEOUT = 30
FIELDS = (
    "id,portal_severity,portal_advisory_type,portal_product_names,"
    "portal_publication_date,portal_update_date,portal_synopsis"
)

def escape_solr(value: str) -> str:
    return value.replace(" ", "\\ ")

def product_filter_candidates(product: str, version: str) -> list:
    esc = escape_solr(product)
    return [
        ("produto|*|versão|*", f"portal_product_filter:{esc}|*|{version}|*"),
        ("produto|*|versão|", f"portal_product_filter:{esc}|*|{version}|"),
        ("nome do produto + versão na synopsis", f'portal_product_names:"{product}" AND portal_synopsis:"{version}"'),
    ]

def parse_date(value):
    """Converte strings (como '2026-05-12T00:00:00Z') em datetime (UTC)."""
    if not value:
        return None
    s_value = str(value).strip()
    if s_value.endswith('Z'):
        s_value = s_value[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(s_value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    # Fallback para YYYY-MM-DD
    try:
        dt = datetime.strptime(s_value[:10], "%Y-%m-%d")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

def request_page(session: requests.Session, product_fq: str, start: int) -> dict:
    params = {
        "q": "*:*",
        "rows": ROWS,
        "start": start,
        "sort": "portal_update_date desc",
        "fq": ['documentKind:("Errata")', product_fq],
        "fl": FIELDS,
        "wt": "json",
    }
    headers = {"Accept": "application/json", "User-Agent": "errata-report/2.0"}
    prepared = requests.Request("GET", API_URL, params=params, headers=headers).prepare()

    try:
        response = session.send(prepared, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as exc:
        print(f"[ERRO] Falha na requisição da API: {exc}")
    return {}

def fetch_all(session: requests.Session, product_fq: str, cutoff: datetime) -> list:
    docs_all = []
    start = 0
    for _ in range(MAX_PAGES):
        data = request_page(session, product_fq, start)
        response = data.get("response", {})
        docs = response.get("docs", [])
        total = response.get("numFound", 0)
        
        if not docs:
            break
        docs_all.extend(docs)
        start += len(docs)
        
        if start >= total:
            break
            
        last_update = parse_date(docs[-1].get("portal_update_date"))
        if cutoff and last_update and last_update < cutoff:
            break
    return docs_all

def fetch_errata(product: str, version: str, cutoff: datetime) -> list:
    with requests.Session() as session:
        for label, product_fq in product_filter_candidates(product, version):
            docs = fetch_all(session, product_fq, cutoff)
            if docs:
                return docs
            print(f"  [AVISO] Filtro '{label}' retornou 0 resultados.")
    return []

# tratamento de dados
def as_text(value) -> str:
    if value is None: return ""
    if isinstance(value, (list, tuple)): return ", ".join(str(v) for v in value)
    return str(value)

def severity_class(severity: str) -> str:
    sev = (severity or "").strip().lower()
    if sev in ("important", "critical"): return "sev-high"
    if sev == "moderate": return "sev-moderate"
    if sev == "low": return "sev-low"
    return "sev-none"

def filter_and_format_errata(docs: list, start_date: datetime, end_date: datetime) -> list:
    """Filtra pelas datas exatas, tipo de advisory, e formata para o template."""
    wanted = {t.lower() for t in ADVISORY_TYPES}
    result = []
    for doc in docs:
        pub_date = parse_date(doc.get("portal_publication_date"))
        if not pub_date:
            continue
            
        # Filtro de Período data inicial e final
        if start_date and pub_date < start_date: continue
        if pub_date > end_date: continue
            
        # Filtro de Advisory Type
        adv_type = as_text(doc.get("portal_advisory_type"))
        if wanted and adv_type.lower() not in wanted:
            continue
            
        upd_date = parse_date(doc.get("portal_update_date")) or pub_date
        sev = as_text(doc.get("portal_severity")) or "None"
        errata_id = as_text(doc.get("id"))
        
        # Cria um dicionário limpo para facilitar o uso no Jinja2
        result.append({
            "id": errata_id,
            "url": ERRATA_URL.format(id=errata_id),
            "synopsis": as_text(doc.get("portal_synopsis")),
            "advisory_type": adv_type,
            "severity": sev,
            "severity_class": severity_class(sev),
            "products": as_text(doc.get("portal_product_names")),
            "pub_date": pub_date,
            "upd_date": upd_date
        })
        
    result.sort(key=lambda d: (d["pub_date"], d["upd_date"]), reverse=True)
    return result

# gera relatorio 
def save_report(report_data: list, generated_at: datetime):
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    try:
        template = env.get_template(TEMPLATE_FILE)
    except Exception as exc:
        print(f"\n[ERRO] Não foi possível carregar o template HTML '{TEMPLATE_FILE}' na pasta '{TEMPLATE_DIR}'.\nErro: {exc}")
        sys.exit(1)

    # Renderiza passando os dados e a data atual
    html_content = template.render(report_data=report_data, generated_at=generated_at)

    # Salva em arquivo
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"Report_Erratas_Consolidado_{generated_at.strftime('%Y%m%d_%H%M%S')}.html"
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return path

def main():
    if not os.path.exists(YAML_FILE):
        print(f"[ERRO] O arquivo YAML '{YAML_FILE}' não foi encontrado.")
        sys.exit(1)

    with open(YAML_FILE, 'r', encoding='utf-8') as file:
        try:
            config = yaml.safe_load(file)
        except yaml.YAMLError as exc:
            print(f"[ERRO] Erro ao analisar o YAML: {exc}")
            sys.exit(1)

    products = config.get("products", [])
    if not products:
        print("[AVISO] Nenhum produto encontrado no arquivo YAML sob a chave 'products'.")
        sys.exit(0)

    # Data/Hora do momento em que o script está sendo executado
    now_utc = datetime.now(timezone.utc)
    report_data = []

    print("=" * 60)
    print("Iniciando geração do Relatório Consolidado de Erratas")
    print("=" * 60)

    for item in products:
        product_name = item.get("product")
        version = item.get("version")
        last_version = item.get("last_version")
        date_str = item.get("date")

        # Define data inicial baseada na YAML ou assume Default (None) se for 'null'
        start_date = parse_date(date_str) if date_str else DEFAULT_START_DATE

        print(f"\n[INFO] Consultando: {product_name} | Versão: {version}")
        if start_date:
            print(f"       Período: {start_date.strftime('%d/%m/%Y %H:%M:%S')} a {now_utc.strftime('%d/%m/%Y %H:%M:%S')} (UTC)")
        else:
            print(f"       Período: 'Data inicial não registrada' a {now_utc.strftime('%d/%m/%Y %H:%M:%S')} (UTC)")

        # Consulta e Filtra a API da Red Hat
        docs = fetch_errata(product_name, version, start_date)
        errata_formatada = filter_and_format_errata(docs, start_date, now_utc)
        
        print(f"       -> {len(errata_formatada)} errata(s) encontrada(s) no período.")

        # Adiciona à lista geral que vai para o Template 
        report_data.append({
            "product": product_name,
            "version": version,
            "last_version": last_version,
            "start_date": start_date,
            "end_date": now_utc,
            "errata": errata_formatada
        })

    print("\n" + "=" * 60)
    
    # Gera HTML 
    path = save_report(report_data, now_utc)
    print(f"[OK] Relatório Consolidado salvo com sucesso em: {path}")

if __name__ == "__main__":
    main()