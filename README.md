# Data Breach Monitoring System

Plataforma web de monitorização de fugas de dados (data breaches) com integração de IA.

**Live:** https://api-proxy-render.vercel.app

## Arquitetura

```
Utilizador → Vercel (Frontend) → Render (Backend v1.4.0) → HIBP API
                                       ↕                       ↓
                                  Hugging Face            Breach Data
                               (AI + Dataset)
```

| Componente | Tecnologia | URL |
|-----------|-----------|-----|
| Frontend | HTML + Tailwind CSS + JS | https://api-proxy-render.vercel.app |
| Backend | Node.js + Express.js | https://backend-proxy-s43a.onrender.com |
| API Breaches | Have I Been Pwned API v3 | https://haveibeenpwned.com/API/v3 |
| IA + Dataset | Hugging Face | https://huggingface.co/datasets/Tiago2024180/eyewebdataset |

## Funcionalidades

### Verificação de Breaches
- **Email Check** — verifica se um email aparece em breaches conhecidos (HIBP API)
- **Domain/URL Check** — verifica breaches associados a um domínio
- **Password Check** — verifica passwords comprometidas com k-anonymity (SHA-1, apenas 5 chars enviados)

### Pesquisa de Notícias (14+ fontes)
Quando se pesquisa um domínio, o sistema procura notícias de cibersegurança em:
- Google News RSS (EN + PT)
- Bing News RSS
- GDELT DOC API
- 12 feeds RSS de segurança (BleepingComputer, KrebsOnSecurity, TheHackerNews, SecurityWeek, DarkReading, Naked Security, ThreatPost, Infosecurity Magazine, SC Magazine, Graham Cluley, Troy Hunt, SANS ISC)

### Inteligência Artificial (Hugging Face)
- **Classificação zero-shot** com `facebook/bart-large-mnli` — cada notícia recebe um score de relevância de cibersegurança (6 labels)
- **Dataset automático** — cada pesquisa de domínio grava os resultados no dataset HF (`search_history.jsonl`)
- **Dataset Explorer** — tabela interativa no frontend que mostra o histórico completo

## Segurança
- API keys nunca expostas no frontend (variáveis de ambiente no Render)
- k-Anonymity para passwords (hash parcial, comparação local)
- Rate limiting (60 req/min por IP)
- CORS restrito (só Vercel/Render)
- Proxy pattern (frontend nunca contacta APIs externas diretamente)

## Variáveis de Ambiente (Render)

| Variável | Descrição |
|----------|-----------|
| `HIBP_API_KEY` | Chave da API Have I Been Pwned |
| `HF_TOKEN` | Token Hugging Face (write access) |
| `FRONTEND_URL` | URL do frontend Vercel (CORS) |

## Estrutura do Projeto

```
├── index.html                    # Frontend (Vercel)
├── render.yaml                   # Configuração Render
└── backend-render/
    ├── server.js                 # Backend Express.js (~1100 linhas)
    └── package.json              # Dependências (v1.4.0)
```

## Tecnologias

| Tecnologia | Propósito |
|-----------|----------|
| HTML5 + Tailwind CSS v4 | Frontend |
| Node.js + Express.js | Backend |
| Have I Been Pwned API v3 | Dados de breaches |
| Hugging Face Inference API | Classificação IA (bart-large-mnli) |
| `@huggingface/hub` | Leitura/escrita do dataset |
| `fast-xml-parser` | Parsing de feeds RSS |
| Vercel | Hosting frontend |
| Render | Hosting backend |
| Git/GitHub | Controlo de versões |

## Evolução

| Versão | Descrição |
|--------|-----------|
| v1.0 | Backend proxy HIBP + frontend com check de email |
| v1.1 | CORS fix, fallback Vercel→Render, password check k-anonymity |
| v1.2 | Notícias de 12 RSS feeds + GDELT + Google News + Bing News |
| v1.3 | Integração Hugging Face: IA (bart-large-mnli) + Dataset read/write |
| v1.4 | Flush imediato de escritas HF, Dataset Viewer JSONL, Dataset Explorer no frontend |
