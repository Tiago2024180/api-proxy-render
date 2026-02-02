# Site teste: Vercel (frontend) + Render (backend) + Hugging Face (dataset)

## Arquitetura
- **Vercel**: serve o frontend estático em `frontend/`.
- **Render**: API/Proxy em `backend-render/`.
- **Hugging Face Datasets**: repositório para guardar snapshots do dataset gerado.

## URLs
- Backend (Render): https://backend-proxy-s43a.onrender.com
- Frontend (Vercel): (coloca aqui o teu URL quando estiver ativo)

## Variáveis necessárias

### Render (serviço backend)
- `HIBP_API_KEY` **ou** `HIBP_KEY`: chave da API Have I Been Pwned.
- `FRONTEND_URL`: URL do Vercel (pode ser lista separada por vírgulas).
  - Exemplo: `https://teu-projeto.vercel.app,https://teu-projeto-git-main-....vercel.app`

### GitHub Secrets (Actions)
Para workflows e deploy automático:
- `HIBP_API_KEY` (para o workflow de atualização do dataset)
- `VERCEL_TOKEN`, `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID` (deploy do frontend)
- `HF_TOKEN`, `HF_REPO` (obrigatório para upload do dataset para Hugging Face)

### Vercel (env vars)
- Não precisas de `HIBP_API_KEY` no Vercel.
- O frontend usa `frontend/vercel.json` com rewrite `/api/*` → Render, então `BACKEND_URL` torna-se opcional.

## Hugging Face (primeira utilização)

### 1) Criar conta e um dataset repo
1. Cria conta em https://huggingface.co/
2. Vai a **New** → **Dataset**.
3. Escolhe um nome, por exemplo: `tiago/hibp-breaches-dataset`.
4. Escolhe **Public** (para teste) ou **Private**.

O valor que vais usar no GitHub Secret `HF_REPO` é exatamente o **repo id**:
- Exemplo: `tiago/hibp-breaches-dataset`

### 2) Criar token (HF_TOKEN)
1. Vai a https://huggingface.co/settings/tokens
2. Clica **New token**.
3. Para este caso, usa permissões de escrita (Write) para datasets.
4. Copia o token e guarda-o.

### 3) Colocar secrets no GitHub
1. GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Add **New repository secret**:
   - `HF_TOKEN` = token que copiaste
   - `HF_REPO` = `utilizador/nome-do-dataset`

### 4) Testar manualmente o workflow
1. GitHub → **Actions** → workflow **Update Dataset**
2. Click **Run workflow**
3. No fim, confirma que apareceu um ficheiro em Hugging Face em `datasets/`.

Ficheiros publicados no Hugging Face:
- `datasets/breaches-latest.json` (sempre o snapshot mais recente)
- `datasets/latest.json` (metadados com `generated_at` + nome do snapshot)
- `datasets/breaches-<timestamp>.json` (snapshots versionados)

## Frontend (Vercel rewrite)
O frontend chama `/api/hibp/...` e o Vercel faz proxy para o Render usando:
- `frontend/vercel.json`
