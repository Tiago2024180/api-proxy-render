# HIBP Proxy Backend (v1.4.0)

Backend Node.js/Express.js que serve como proxy para a API Have I Been Pwned, com integração de Hugging Face para IA e armazenamento de dados.

## Endpoints

| Método | Endpoint | Descrição |
|--------|---------|-----------|
| GET | `/` | Health check (versão, status, config) |
| GET | `/api/hibp/check/:email` | Verificar breaches de um email |
| GET | `/api/hibp/breaches` | Listar todos os breaches conhecidos |
| GET | `/api/hibp/domain/:domainOrUrl` | Verificar breaches de um domínio |
| POST | `/api/hibp/password` | Verificar password (k-anonymity) |
| GET | `/api/reports/unverified/:query` | Pesquisar notícias (14+ fontes + IA) |
| GET | `/api/hf/breaches/:domain` | Consultar dataset HF para um domínio |

## Requisitos

- Node.js >= 18
- Variáveis de ambiente: `HIBP_API_KEY`, `HF_TOKEN`

## Execução Local

```bash
cd backend-render
npm install
HIBP_API_KEY=xxx HF_TOKEN=xxx node server.js
```

## Deploy (Render)

O deploy é automático via GitHub → Render (configurado em `render.yaml`).

Variáveis de ambiente necessárias no painel Render:
- `HIBP_API_KEY` — chave API HIBP
- `HF_TOKEN` — token Hugging Face (write)
- `FRONTEND_URL` — URL do frontend Vercel (CORS)

## Dependências

| Pacote | Versão | Propósito |
|--------|--------|----------|
| express | ^4.18.2 | Framework web |
| cors | ^2.8.5 | Cross-Origin Resource Sharing |
| node-fetch | ^2.7.0 | HTTP requests |
| fast-xml-parser | ^5.3.5 | Parsing RSS feeds |
| @huggingface/hub | ^2.8.1 | Leitura/escrita dataset HF |

## Fontes de Notícias

Google News RSS, Bing News RSS, GDELT DOC API, BleepingComputer, KrebsOnSecurity, TheHackerNews, SecurityWeek, DarkReading, Naked Security, ThreatPost, Infosecurity Magazine, SC Magazine, Graham Cluley, Troy Hunt, SANS ISC

## Hugging Face

- **Modelo IA:** `facebook/bart-large-mnli` (zero-shot classification)
- **Dataset:** `Tiago2024180/eyewebdataset`
- **Escrita automática:** cada pesquisa de domínio grava em `search_history.jsonl` + `.autochecks/{domain}.json`

