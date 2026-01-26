/**
 * Backend Proxy para Have I Been Pwned API
 * Deploy no Render.com
 * 
 * IMPORTANTE: Configure a variável de ambiente no Render:
 * HIBP_API_KEY = 1d416ab2ce0f461fa9ae0902a39ba1d7
 */

const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// API Key do Have I Been Pwned (configurar como variável de ambiente no Render!)
const HIBP_API_KEY = process.env.HIBP_API_KEY;

// Middleware
app.use(cors({
    origin: '*', // Em produção, restringir ao domínio do Vercel
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Accept']
}));
app.use(express.json());

// Rate limiting simples (em produção usar redis)
const requestCounts = new Map();
const RATE_LIMIT = 10; // requests por minuto por IP
const RATE_WINDOW = 60000; // 1 minuto

function checkRateLimit(ip) {
    const now = Date.now();
    const windowStart = now - RATE_WINDOW;
    
    if (!requestCounts.has(ip)) {
        requestCounts.set(ip, []);
    }
    
    const requests = requestCounts.get(ip).filter(time => time > windowStart);
    requestCounts.set(ip, requests);
    
    if (requests.length >= RATE_LIMIT) {
        return false;
    }
    
    requests.push(now);
    return true;
}

// Cache simples para evitar chamadas repetidas à API
const cache = new Map();
const CACHE_TTL = 300000; // 5 minutos

function getCached(key) {
    const item = cache.get(key);
    if (item && Date.now() - item.timestamp < CACHE_TTL) {
        console.log(`[Cache] HIT for ${key}`);
        return item.data;
    }
    console.log(`[Cache] MISS for ${key}`);
    return null;
}

function setCache(key, data) {
    cache.set(key, { data, timestamp: Date.now() });
}

// Health check
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'HIBP Proxy Backend',
        version: '1.0.0',
        endpoints: {
            healthCheck: 'GET /',
            checkEmail: 'GET /api/hibp/check/:email',
            getBreaches: 'GET /api/hibp/breaches'
        },
        apiKeyConfigured: !!HIBP_API_KEY
    });
});

// Endpoint principal: Verificar email por vazamentos
app.get('/api/hibp/check/:email', async (req, res) => {
    const { email } = req.params;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    console.log(`[Request] Check email: ${email} from ${clientIP}`);
    
    // Validar email
    if (!email || !email.includes('@')) {
        return res.status(400).json({ error: 'Email inválido' });
    }
    
    // Rate limiting
    if (!checkRateLimit(clientIP)) {
        console.log(`[RateLimit] Blocked ${clientIP}`);
        return res.status(429).json({ error: 'Muitas requisições. Tente novamente em 1 minuto.' });
    }
    
    // Verificar API key
    if (!HIBP_API_KEY) {
        console.error('[Error] HIBP_API_KEY não configurada!');
        return res.status(500).json({ error: 'API Key não configurada no servidor' });
    }
    
    // Verificar cache
    const cacheKey = email.toLowerCase();
    const cachedResult = getCached(cacheKey);
    if (cachedResult !== null) {
        return res.status(cachedResult.status).json(cachedResult.data);
    }
    
    try {
        // Chamada à API do Have I Been Pwned
        const hibpUrl = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;
        
        console.log(`[HIBP] Calling API for ${email}`);
        
        const response = await fetch(hibpUrl, {
            method: 'GET',
            headers: {
                'hibp-api-key': HIBP_API_KEY,
                'user-agent': 'DataBreachChecker-Backend/1.0',
                'Accept': 'application/json'
            }
        });
        
        console.log(`[HIBP] Response status: ${response.status}`);
        
        // Email não encontrado em vazamentos
        if (response.status === 404) {
            setCache(cacheKey, { status: 404, data: [] });
            return res.status(404).json([]);
        }
        
        // Rate limit da HIBP
        if (response.status === 429) {
            const retryAfter = response.headers.get('retry-after') || 2;
            console.log(`[HIBP] Rate limited, retry after ${retryAfter}s`);
            return res.status(429).json({ 
                error: 'Rate limit da API HIBP excedido', 
                retryAfter: parseInt(retryAfter) 
            });
        }
        
        // Erro de autenticação
        if (response.status === 401) {
            console.error('[HIBP] API Key inválida!');
            return res.status(401).json({ error: 'API Key inválida' });
        }
        
        // Outros erros
        if (!response.ok) {
            const errorText = await response.text();
            console.error(`[HIBP] Error: ${response.status} - ${errorText}`);
            return res.status(response.status).json({ error: errorText });
        }
        
        // Sucesso - email encontrado em vazamentos
        const breaches = await response.json();
        console.log(`[HIBP] Found ${breaches.length} breaches for ${email}`);
        
        // Cache do resultado
        setCache(cacheKey, { status: 200, data: breaches });
        
        return res.json(breaches);
        
    } catch (error) {
        console.error(`[Error] ${error.message}`);
        return res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
    }
});

// Endpoint: Listar todas as breaches conhecidas
app.get('/api/hibp/breaches', async (req, res) => {
    console.log('[Request] List all breaches');
    
    if (!HIBP_API_KEY) {
        return res.status(500).json({ error: 'API Key não configurada' });
    }
    
    // Verificar cache
    const cachedBreaches = getCached('all_breaches');
    if (cachedBreaches !== null) {
        return res.json(cachedBreaches.data);
    }
    
    try {
        const response = await fetch('https://haveibeenpwned.com/api/v3/breaches', {
            headers: {
                'hibp-api-key': HIBP_API_KEY,
                'user-agent': 'DataBreachChecker-Backend/1.0'
            }
        });
        
        if (!response.ok) {
            return res.status(response.status).json({ error: 'Erro ao buscar breaches' });
        }
        
        const breaches = await response.json();
        setCache('all_breaches', { status: 200, data: breaches });
        
        return res.json(breaches);
        
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
});

// Endpoint: Estatísticas do servidor
app.get('/api/stats', (req, res) => {
    res.json({
        cacheSize: cache.size,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📡 HIBP API Key configured: ${HIBP_API_KEY ? 'Yes' : 'NO - Please set HIBP_API_KEY env var!'}`);
});
