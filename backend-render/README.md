# HIBP Proxy Backend

Instruções rápidas para executar e deploy deste backend (Proxy para Have I Been Pwned).

Requisitos locais
- Node.js (>=18) e npm instalados e disponíveis no PATH.

Execução local
1. Abra um terminal na pasta `backend-render`.
2. Instale dependências:

```powershell
npm install
```

3. Configure a variável de ambiente `HIBP_API_KEY` (opcional para começar, mas necessária para endpoints HIBP).

4. Inicie o servidor:

```powershell
npm start
# ou
node index.js
```

Deploy no Render
- O `package.json` define `main: server.js` e `start: node server.js`.
- Adicionámos um `index.js` compatível para plataformas que executam `node index.js` por omissão.
- No painel do Render, defina a variável de ambiente `HIBP_API_KEY` com a sua chave.
- Configure o comando de start como `npm start` (opcional) ou deixe em branco para que o Render execute `node index.js`.

Testes
- Use o script `test-health.ps1` para verificar `GET /` e `GET /api/stats`.

Notas
- Se o serviço remoto estiver a responder 503, verifique os logs do Render e se o `HIBP_API_KEY` está configurado.

Redeploy automatizado

```powershell
# (1) Atualizar localmente e testar
cd backend-render
npm install
node index.js # ou npm start
Integração contínua (CI)
- Foi adicionado um workflow GitHub Actions em `.github/workflows/ci-backend.yml` que:
	- instala Node.js 18;
	- executa `npm install` em `backend-render`;
	- inicia o servidor em background e testa `GET /` e `GET /api/stats`;
	- carrega o `server.log` como artefacto para inspeção.

Como usar o CI
- Faz commit e push destas alterações para o branch `main` (ou `master`) ou dispara manualmente o workflow na aba Actions do GitHub.
- O workflow dará feedback nos logs e guardará `server.log` como artefacto para download.

Atualização de datasets (Hugging Face)
- Scripts:
	- `backend-render/scripts/update_dataset.js`: busca a lista de breaches do HIBP e grava em `backend-render/datasets`.
	- `backend-render/scripts/upload_to_hf.py`: usa `huggingface_hub` para enviar o ficheiro `latest.json` para o repositório HF configurado.

- Workflow GitHub Actions: `.github/workflows/update-dataset.yml` executa diariamente (ou manualmente) para gerar o dataset e, se definidos, faz upload para HF usando os secrets `HF_TOKEN` e `HF_REPO`.

Configuração:
- Na página do repositório no GitHub, adicione os secrets `HIBP_API_KEY` (necessário), `HF_TOKEN` e `HF_REPO` (opcionais) em Settings → Secrets → Actions.


# (2) Commit & push
cd ..
.\deploy-to-render.ps1 -Message "chore: deploy backend-render updates"

# (3) No painel do Render: verifique que o serviço está ligado ao repositório e que `render.yaml` está presente.
# (4) No painel do serviço: defina a variável `HIBP_API_KEY` em Environment -> Environment Variables.
# (5) Trigger manual deploy ou aguarde o webhook do GitHub.
```

