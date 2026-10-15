import os
import sys
import yaml
from datetime import datetime, timezone
import requests
from jinja2 import Environment, FileSystemLoader
import re

VERSION_RE = re.compile(r'(?<![\d.])(\d+)\.(\d+)(?:\.\d+)*(?!\d)')
DEBUG_VERSIONS = False  # True: imprime versões detectadas e a origem de cada errata
INCLUDE_UNKNOWN_VERSION = False  

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
MAX_PAGES = 20
TIMEOUT = 30
FIELDS = (
    "id,portal_severity,portal_advisory_type,portal_product_names,"
    "portal_publication_date,portal_update_date,portal_synopsis,"
    "portal_product_filter"
)


def escape_solr(value: str) -> str:
    return value.replace(" ", "\\ ")

def product_filter_candidates(product: str, version: str) -> list:
    esc = escape_solr(product)
    return [
        ("qualquer versão do produto", f"portal_product_filter:{esc}|*"),
        ("nome do produto na synopsis", f'portal_product_names:"{product}"'),
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

def request_page(session: requests.Session, product_fq: str, start: int, cutoff: datetime = None) -> dict:
    fq = ['documentKind:("Errata")', product_fq]
    if cutoff:
        since = cutoff.astimezone(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        fq.append(f"portal_publication_date:[{since} TO *]")
    params = {
        "q": "*:*",
        "rows": ROWS,
        "start": start,
        "sort": "portal_update_date desc",
        "fq": fq,
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
    """Busca páginas ordenadas por portal_update_date desc e para quando passar do cutoff."""
    docs_all = []
    start = 0
    for _ in range(MAX_PAGES):
        data = request_page(session, product_fq, start, cutoff)
        response = data.get("response", {})
        docs = response.get("docs", [])
        total = response.get("numFound", 0)
        if start == 0:
            print(f"[INFO] Total de documentos encontrados para o filtro '{product_fq}' desde o corte: {total}")
        if not docs:
            break
        docs_all.extend(docs)
        start += len(docs)

        if start >= total:
            break

        # portal_publication_date <= portal_update_date, então se o último update
        # da página é anterior ao cutoff, o restante também é.
        last_update = parse_date(docs[-1].get("portal_update_date"))
        if cutoff and last_update and last_update < cutoff:
            break
    else:
        print(f"  [AVISO] MAX_PAGES ({MAX_PAGES}) atingido; pode haver erratas não baixadas.")
    return docs_all

def fetch_errata(product: str, cutoff: datetime) -> list:
    """Busca erratas do produto (todas as versões); o corte temporal é feito depois."""
    with requests.Session() as session:
        for label, product_fq in product_filter_candidates(product, None):
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
    """Retorna a classe CSS baseada na severidade do advisory."""
    sev = (severity or "").strip().lower()
    if sev in ("important", "critical"): return "sev-high"
    if sev == "moderate": return "sev-moderate"
    if sev == "low": return "sev-low"
    return "sev-none"

def _major_minor(value):
    """'4.20.5' -> (4, 20). Retorna None se não houver versão."""
    m = VERSION_RE.search(str(value or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None

def _versions_in_text(text: str) -> set:
    return {(int(a), int(b)) for a, b in VERSION_RE.findall(text)}

def _versions_from_product_filter(doc: dict, product: str) -> set:
    """Versões do próprio produto em portal_product_filter ('Produto|...|Versão|...')."""
    raw = doc.get("portal_product_filter") or []
    if isinstance(raw, str):
        raw = [raw]
    found = set()
    for f in raw:
        parts = [p.strip() for p in str(f).split("|")]
        if len(parts) >= 3 and parts[0].lower() == product.lower() and parts[2] != "*":
            mm = _major_minor(parts[2])
            if mm:
                found.add(mm)
    return found

def match_version(doc: dict, product: str, target: str):
    """Retorna (bool|None, origem). None = versão não identificável em nenhum campo."""
    tgt = _major_minor(target)
    if not tgt:
        return False, "target inválido"

    meta = _versions_from_product_filter(doc, product)
    syn = _versions_in_text(as_text(doc.get("portal_synopsis")))

    # Metadado estruturado
    if meta:
        if tgt not in meta:
            return False, "portal_product_filter"
        # Se o metadado lista várias linhas, a sinopse desempata
        narrowed = syn & meta
        if narrowed and tgt not in narrowed:
            return False, "portal_synopsis"
        return True, "portal_product_filter"

    if syn:
        return tgt in syn, "portal_synopsis"

    names = _versions_in_text(as_text(doc.get("portal_product_names")))
    if names:
        return tgt in names, "portal_product_names"

    return None, None

def filter_and_format_errata(docs: list, start_date: datetime, end_date: datetime, product: str, version: str) -> list:
    """Filtra por data, versão exata (major.minor) e tipo de advisory; formata para o template."""
    wanted = {t.lower() for t in ADVISORY_TYPES}
    result = []
    unknown = []
    in_period = 0
    for doc in docs:
        pub_date = parse_date(doc.get("portal_publication_date"))
        if not pub_date:
            continue

        if start_date and pub_date.date() < start_date.date(): continue
        if pub_date > end_date: continue
        in_period += 1     

        # Tipo de advisory
        adv_type = as_text(doc.get("portal_advisory_type"))
        if wanted and adv_type.lower() not in wanted:
            continue

        # Versão exata
        ok, source = match_version(doc, product, version)
        if DEBUG_VERSIONS:
            print(f"       [DEBUG] {doc.get('id')} -> {ok} ({source}) | "
                  f"filter={doc.get('portal_product_filter')} | syn={doc.get('portal_synopsis')}")
        if ok is None:
            unknown.append(as_text(doc.get("id")))
            if not INCLUDE_UNKNOWN_VERSION:
                continue
        elif not ok:
            continue

        upd_date = parse_date(doc.get("portal_update_date")) or pub_date
        sev = as_text(doc.get("portal_severity")) or "None"
        errata_id = as_text(doc.get("id"))

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

    if unknown:
        print(f"       [INFO] {in_period} publicada(s) no período (todas as versões); {len(result)} na versão {version}.")

    result.sort(key=lambda d: (d["pub_date"], d["upd_date"]), reverse=True)
    return result


# gera relatorio 
def save_report(report_data: list, generated_at: datetime):
    """Salva o relatório em HTML usando Jinja2 e retorna o caminho do arquivo gerado."""
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
        version = str(item.get("version")).strip()
        start_date = parse_date(item.get("date"))

        if not start_date:
            print(f"[AVISO] '{product_name}' sem 'date' válido no YAML; sem corte inicial.")
            start_date = DEFAULT_START_DATE

        print(f"\n[INFO] Consultando: {product_name} | Versão da Empresa: {version} | "
              f"Desde: {start_date.isoformat() if start_date else 'sem data'}")

        docs = fetch_errata(product_name, start_date)
        errata_formatada = filter_and_format_errata(docs, start_date, now_utc, product_name, version)

        print(f"       -> {len(docs)} baixada(s), {len(errata_formatada)} dentro do período.")

        report_data.append({
            "product": product_name,
            "version": version,
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