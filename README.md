# 🛡️ DFIR IRIS — SOC Dashboard & Relatórios

Ferramenta para extração de relatórios de produtividade (MTTA/MTTR) via API do DFIR IRIS e visualização em Dashboard HTML.

## 📦 Instalação
bash
pip install -r requirements.txt

## ⚙️ Configuração
1. Copie o arquivo `.env.example` para `.env`.
2. Preencha com a URL e o Token da sua API do IRIS.

## 🚀 Como usar
Para gerar os relatórios dos últimos 30 dias:
```bash

# Todos os analistas — últimos 30 dias (sumário)
python iris_analyst_report.py --days 30

# Período específico
python iris_analyst_report.py --from 01/05/2026 --to 26/05/2026

# Dia específico
python iris_analyst_report.py --date 26/05/2026

# Um analista específico
python iris_analyst_report.py --days 30 --analyst rodolfo.marques

# Com lista detalhada de alertas e cases
python iris_analyst_report.py --days 30 --show-alerts --show-cases

# Só cases (sem alertas — mais rápido)
python iris_analyst_report.py --days 30 --no-alerts --show-cases

# Exportar JSON
python iris_analyst_report.py --days 30 --out resultados\analistas.json

# Completo: analista + período + detalhes + JSON
python iris_analyst_report.py --from 01/05/2026 --to 26/05/2026 --analyst analista01 --show-alerts --show-cases --out resultados\analista01.csv


Após gerar os CSVs, abra o arquivo dashboard_SOC.html no seu navegador e carregue a pasta com os resultados.