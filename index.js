const express = require('express');
const axios = require('axios');
const cors = require('cors'); // Importante para permitir o frontend aceder
const app = express();

app.use(express.json());
app.use(cors()); // Ativa o CORS

app.get('/api/check/:email', async (req, res) => {
  try {
    const response = await axios.get(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${req.params.email}`,
      {
        headers: {
          'hibp-api-key': process.env.HIBP_API_KEY,
          'User-Agent': 'DataLeak-Sentinel'
        }
      }
    );
    res.json(response.data);
  } catch (error) {
    if (error.response && error.response.status === 404) {
      // 404 significa que não houve violações encontradas
      return res.json([]); 
    }
    res.status(500).json({ error: 'Erro ao consultar API' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor a rodar na porta ${PORT}`);
});