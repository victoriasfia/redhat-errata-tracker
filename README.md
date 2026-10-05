# Red Hat Errata Report Generator

Este é um script em Python que consulta automaticamente a API pública da Red Hat (Hydra / Solr) para buscar atualizações, correções de bugs e alertas de segurança (RHSA, RHBA, RHEA) de produtos específicos. Ao final, ele gera um relatório HTML limpo, formatado e responsivo.

---
## Funcionalidades
* **Busca Inteligente**: Utiliza filtros de fallback para garantir que o produto seja encontrado, mesmo com inconsistências na taxonomia da API da Red Hat (tenta estrutura hierárquica e busca em texto livre).

+ **Filtragem por Período e Tipo**: Permite definir um limite de dias (ex: últimos 50 dias) e escolher quais tipos de erratas importar (Bug Fix, Security, Enhancement).

* **Relatório HTML**: Gera um arquivo HTML único com CSS embutido, dispensando dependências externas, contendo links diretos para a documentação oficial de cada errata.
---
## Pré-requisitos
* *Python 3*
---
## Configuração antes de executar 

```python
# Configurações do relatório

# nome exato do produto (ex: "Red Hat OpenShift Container Platform")
PRODUCT = "Red Hat OpenShift GitOps" 
# escolha a versão
VERSION = "1.21"
# Quantos dias para trás o script deve buscar
DAYS_BACK = 120
```

## Como executar

Clone o projeto e acesse o diretório
```python
  git clone https://github.com/victoriasfia/redhat-errata-tracker
  cd reports # entre no diretório
```
Instale as dependências 
```python
  pip install -r requirements.txt 
```

Execute o projeto
```python
  python3 script_report.py
```

## Resultado
O script criará automaticamente uma pasta chamada `generated_reports` no mesmo diretório em que foi executado.

Dentro dela, você encontrará o relatório gerado, por exemplo: `Report_Erratas_20261005_1711.html`. Basta abrir este arquivo em qualquer navegador web para visualizar a tabela de correções classificada por severidade e data.