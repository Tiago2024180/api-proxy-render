/**
 * Backend Proxy para Have I Been Pwned API
 * Deploy no Render.com
 * 
 * IMPORTANTE: Configure a variável de ambiente no Render:
 * HIBP_API_KEY (Nunca faça commit/partilha da chave em repositórios ou chats.)
 */

const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const crypto = require('crypto');
const path = require('path');
const { XMLParser } = require('fast-xml-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Behind Render/Cloudflare (and optionally Vercel rewrite), we need to trust proxy headers
// so req.ip reflects the real client rather than the edge proxy.
app.set('trust proxy', 1);

let APP_VERSION = 'unknown';
try {
    // Keep version in sync with package.json for easier deploy verification.
    // eslint-disable-next-line global-require, import/no-dynamic-require
    APP_VERSION = require(path.join(__dirname, 'package.json')).version || 'unknown';
} catch {
    APP_VERSION = 'unknown';
}

// API Key do Have I Been Pwned (configurar como variável de ambiente no Render!)
// Accept both names to avoid env-var mismatch between environments.
const HIBP_API_KEY = process.env.HIBP_API_KEY || process.env.HIBP_KEY;

// Middleware
// CORS: allow requests from FRONTEND_URL (can be comma-separated list).
// Also allow Vercel/Render hosts to avoid cross-origin failures when using direct Render fallback.
const frontendEnv = process.env.FRONTEND_URL || '';
const allowedOrigins = frontendEnv ? frontendEnv.split(',').map(s => s.trim()).filter(Boolean) : ['*'];

function isAllowedOrigin(origin) {
    if (!origin) return true;
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return true;

    const lower = origin.toLowerCase();
    if (lower.endsWith('.vercel.app')) return true;
    if (lower.endsWith('.onrender.com')) return true;

    return false;
}

app.use(cors({
    origin: function(origin, callback) {
        // allow non-browser requests (e.g., curl, server-to-server) when origin is undefined
        if (isAllowedOrigin(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Accept']
}));
app.use(express.json());

// Return JSON on malformed bodies instead of an HTML error.
app.use((err, req, res, next) => {
    if (err && err.type === 'entity.parse.failed') {
        return res.status(400).json({ error: 'Invalid JSON body' });
    }
    return next(err);
});

// Rate limiting simples (em produção usar redis)
const requestCounts = new Map();
const RATE_LIMIT = 60; // requests por minuto por IP
const RATE_WINDOW = 60000; // 1 minuto

function getClientIP(req) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
        // format: client, proxy1, proxy2
        return xff.split(',')[0].trim();
    }
    return req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
}

async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...(options || {}), signal: controller.signal });
    } finally {
        clearTimeout(timeout);
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

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

const REPORTS_TTL = 600000; // 10 minutos
const RSS_FEEDS = [
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
    { name: 'TheRecord', url: 'https://therecord.media/feed/' },
    { name: 'KrebsOnSecurity', url: 'https://krebsonsecurity.com/feed/' },
    { name: 'HIBP Blog', url: 'https://www.troyhunt.com/feed/' },
    { name: 'TheHackerNews', url: 'https://feeds.feedburner.com/TheHackersNews' },
    { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
    { name: 'TheRegisterSecurity', url: 'https://www.theregister.com/security/headlines.atom' },
    { name: 'ReutersTopNews', url: 'https://feeds.reuters.com/reuters/topNews' },
    { name: 'BBCTechnology', url: 'http://feeds.bbci.co.uk/news/technology/rss.xml' },
    { name: 'TheVerge', url: 'https://www.theverge.com/rss/index.xml' },
    { name: 'ArsTechnica', url: 'http://feeds.arstechnica.com/arstechnica/index' },
    { name: 'Wired', url: 'https://www.wired.com/feed/rss' }
];

const SECURITY_TERMS = [
    'breach', 'breached', 'hacked', 'hack', 'data leak', 'leak', 'leaked',
    'ransomware', 'malware', 'phishing', 'credential', 'credentials',
    'vulnerability', 'exploit', 'zero-day', 'exposed', 'exposure',
    'data theft', 'extortion'
];

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

function isCacheValid(item, ttlMs) {
    return item && Date.now() - item.timestamp < ttlMs;
}

function getRootDomain(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/^www\./, '');
    const parts = host.split('.').filter(Boolean);
    if (parts.length <= 2) return host;
    return parts.slice(-2).join('.');
}

function buildKeywords(query, type) {
    const raw = String(query || '').trim().toLowerCase();
    if (!raw) return [];

    if (type === 'email' && raw.includes('@')) {
        const domain = raw.split('@').pop();
        const root = getRootDomain(domain);
        const brand = root.split('.')[0];
        return [domain, root, brand].filter(Boolean);
    }

    if (type === 'url' || raw.includes('://')) {
        try {
            const u = new URL(raw);
            const root = getRootDomain(u.hostname);
            const brand = root.split('.')[0];
            return [u.hostname, root, brand].filter(Boolean);
        } catch {
            // fallthrough
        }
    }

    if (type === 'domain') {
        const root = getRootDomain(raw);
        const brand = root.split('.')[0];
        return [raw, root, brand].filter(Boolean);
    }

    return [raw];
}

function normalizeItems(feedName, data) {
    // RSS 2.0: data.rss.channel.item
    const rssItems = data && data.rss && data.rss.channel && data.rss.channel.item;
    if (Array.isArray(rssItems)) {
        return rssItems.map(item => ({
            title: item.title || '',
            link: item.link || '',
            pubDate: item.pubDate || item.date || '',
            source: feedName,
            snippet: item.description || item.summary || item['content:encoded'] || ''
        }));
    }
    // Atom: data.feed.entry
    const atomItems = data && data.feed && data.feed.entry;
    if (Array.isArray(atomItems)) {
        return atomItems.map(item => ({
            title: item.title && item.title['#text'] ? item.title['#text'] : (item.title || ''),
            link: item.link && item.link.href ? item.link.href : (item.link || ''),
            pubDate: item.updated || item.published || '',
            source: feedName,
            snippet: (item.summary && item.summary['#text']) ? item.summary['#text'] : (item.summary || item.content || '')
        }));
    }
    return [];
}

async function fetchRssItems() {
    const cacheKey = 'reports:rss_items';
    const cached = cache.get(cacheKey);
    if (isCacheValid(cached, REPORTS_TTL)) return cached.data;

    const parser = new XMLParser({ ignoreAttributes: false });
    const allItems = [];

    for (const feed of RSS_FEEDS) {
        try {
            const res = await fetchWithTimeout(feed.url, { method: 'GET' }, 15000);
            if (!res.ok) continue;
            const xml = await res.text();
            const data = parser.parse(xml);
            const items = normalizeItems(feed.name, data);
            allItems.push(...items);
        } catch {
            // ignore feed failures
        }
    }

    setCache(cacheKey, allItems);
    return allItems;
}

function matchItems(items, keywords) {
    const kw = keywords.map(k => k.toLowerCase()).filter(k => k.length >= 3);
    if (kw.length === 0) return [];

    const seen = new Set();
    const results = [];
    for (const item of items) {
        const hay = `${item.title} ${item.link} ${item.snippet || ''}`.toLowerCase();
        const matchedKeywords = kw.filter(k => hay.includes(k));
        const matchedSignals = SECURITY_TERMS.filter(t => hay.includes(t));

        if (matchedKeywords.length > 0) {
            const key = item.link || item.title;
            if (key && !seen.has(key)) {
                seen.add(key);
                results.push({
                    ...item,
                    reason: {
                        matchedKeywords,
                        matchedSignals
                    }
                });
            }
        }
    }
    return results.slice(0, 8);
}

async function fetchGdeltItems(query, type) {
    const keywords = buildKeywords(query, type);
    const kw = keywords.map(k => k.toLowerCase()).filter(k => k.length >= 3);
    if (kw.length === 0) return [];

    const topicQuery = kw.map(k => `"${k}"`).join(' OR ');
    const signalQuery = SECURITY_TERMS.map(t => `"${t}"`).join(' OR ');
    const fullQuery = `(${topicQuery}) AND (${signalQuery})`;

    const url = `https://api.gdeltproject.org/api/v2/doc/doc?query=${encodeURIComponent(fullQuery)}&mode=ArtList&maxrecords=15&format=json&sort=DateDesc`;
    try {
        const res = await fetchWithTimeout(url, { method: 'GET' }, 15000);
        if (!res.ok) return [];
        const data = await res.json();
        const articles = Array.isArray(data.articles) ? data.articles : [];
        return articles.map(a => {
            const title = a.title || '';
            const link = a.url || '';
            const pubDate = a.seendate || '';
            const snippet = a.extras && a.extras.description ? a.extras.description : (a.description || '');
            const hay = `${title} ${link} ${snippet}`.toLowerCase();
            const matchedKeywords = kw.filter(k => hay.includes(k));
            const matchedSignals = SECURITY_TERMS.filter(t => hay.includes(t));
            return {
                title,
                link,
                pubDate,
                source: 'GDELT',
                snippet,
                reason: { matchedKeywords, matchedSignals }
            };
        });
    } catch {
        return [];
    }
}

// Health check
app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'HIBP Proxy Backend',
        version: APP_VERSION,
        endpoints: {
            healthCheck: 'GET /',
            checkEmail: 'GET /api/hibp/check/:email',
            getBreaches: 'GET /api/hibp/breaches',
            checkDomain: 'GET /api/hibp/domain/:domainOrUrl',
            checkPassword: 'POST /api/hibp/password',
            unverifiedReports: 'GET /api/reports/unverified/:query?type=email|domain|url'
        },
        apiKeyConfigured: !!HIBP_API_KEY
    });
});

// Unverified reports endpoint (news/RSS based, not breach databases)
app.get('/api/reports/unverified/:query', async (req, res) => {
    const { query } = req.params;
    const type = String(req.query.type || 'domain').toLowerCase();
    const keywords = buildKeywords(query, type);

    if (!query || keywords.length === 0) {
        return res.status(400).json({ error: 'Query inválida', results: [] });
    }

    const cacheKey = `reports:unverified:${type}:${String(query).toLowerCase()}`;
    const cached = cache.get(cacheKey);
    if (isCacheValid(cached, REPORTS_TTL)) {
        return res.json(cached.data);
    }

    try {
        const items = await fetchRssItems();
        const rssResults = matchItems(items, keywords);
        const gdeltResults = await fetchGdeltItems(query, type);

        const merged = [];
        const seen = new Set();
        for (const item of [...gdeltResults, ...rssResults]) {
            const key = item.link || item.title;
            if (key && !seen.has(key)) {
                seen.add(key);
                merged.push(item);
            }
        }

        const payload = {
            query,
            type,
            keywords,
            sources: [...RSS_FEEDS.map(f => f.name), 'GDELT'],
            results: merged.slice(0, 10)
        };

        setCache(cacheKey, payload);
        return res.json(payload);
    } catch (error) {
        return res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
    }
});

function normalizeDomainOrUrl(input) {
    const raw = String(input || '').trim();
    if (!raw) return null;
    // If it looks like a URL, extract hostname.
    if (raw.includes('://')) {
        try {
            const u = new URL(raw);
            return u.hostname;
        } catch {
            return null;
        }
    }
    // Otherwise treat as domain.
    const cleaned = raw.replace(/^\s+|\s+$/g, '').toLowerCase();
    // very basic sanity check
    if (cleaned.includes('/') || cleaned.includes(' ')) return null;
    return cleaned;
}

// Endpoint: Check if a domain/URL appears in known breaches (HIBP /breaches?domain=...)
app.get('/api/hibp/domain/:domainOrUrl', async (req, res) => {
    const { domainOrUrl } = req.params;
    const clientIP = getClientIP(req);

    const domain = normalizeDomainOrUrl(domainOrUrl);
    console.log(`[Request] Check domain: ${domainOrUrl} (normalized: ${domain}) from ${clientIP}`);

    if (!domain) {
        return res.status(400).json({ error: 'Domínio/URL inválido' });
    }

    if (!checkRateLimit(clientIP)) {
        console.log(`[RateLimit] Blocked ${clientIP}`);
        return res.status(429).json({ error: 'Muitas requisições. Tente novamente em 1 minuto.' });
    }

    if (!HIBP_API_KEY) {
        return res.status(500).json({ error: 'API Key não configurada no servidor' });
    }

    const cacheKey = `domain:${domain}`;
    const cachedResult = getCached(cacheKey);
    if (cachedResult !== null) {
        return res.status(cachedResult.status).json(cachedResult.data);
    }

    try {
        const hibpUrl = `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`;
        const response = await fetch(hibpUrl, {
            method: 'GET',
            headers: {
                'hibp-api-key': HIBP_API_KEY,
                'user-agent': 'DataBreachChecker-Backend/1.0',
                'Accept': 'application/json'
            }
        });

        if (response.status === 404) {
            setCache(cacheKey, { status: 200, data: [] });
            return res.json([]);
        }

        if (response.status === 429) {
            const retryAfter = response.headers.get('retry-after') || 2;
            return res.status(429).json({
                error: 'Rate limit da API HIBP excedido',
                retryAfter: parseInt(retryAfter)
            });
        }

        if (response.status === 401) {
            return res.status(401).json({ error: 'API Key inválida' });
        }

        if (!response.ok) {
            const errorText = await response.text();
            return res.status(response.status).json({ error: errorText });
        }

        const breaches = await response.json();
        setCache(cacheKey, { status: 200, data: breaches });
        return res.json(breaches);
    } catch (error) {
        return res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
    }
});

// Endpoint: Check password using HIBP Pwned Passwords (k-anonymity range API)
// Accepts JSON: { "sha1": "<40 hex>" } OR { "password": "..." }
// Prefer sending sha1 from the client to avoid sending plaintext passwords.
app.post('/api/hibp/password', async (req, res) => {
    const clientIP = getClientIP(req);

    if (!checkRateLimit(clientIP)) {
        console.log(`[RateLimit] Blocked ${clientIP}`);
        return res.status(429).json({ error: 'Muitas requisições. Tente novamente em 1 minuto.' });
    }

    const body = req.body || {};
    let sha1 = (body.sha1 || '').toString().trim();

    if (!sha1 && typeof body.password === 'string') {
        // Compute SHA-1 on server only as fallback.
        sha1 = crypto.createHash('sha1').update(body.password, 'utf8').digest('hex');
    }

    sha1 = sha1.toUpperCase();
    if (!/^[A-F0-9]{40}$/.test(sha1)) {
        return res.status(400).json({ error: 'sha1 inválido (esperado 40 chars hex) ou password em falta' });
    }

    const cacheKey = `pw:${sha1}`;
    const cachedResult = getCached(cacheKey);
    if (cachedResult !== null) {
        return res.status(cachedResult.status).json(cachedResult.data);
    }

    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5);

    try {
        const url = `https://api.pwnedpasswords.com/range/${prefix}`;
        // Upstream can occasionally hiccup; do a couple of quick retries with a timeout.
        let response = null;
        let lastErr = null;
        for (let attempt = 1; attempt <= 3; attempt++) {
            try {
                response = await fetchWithTimeout(url, {
                    method: 'GET',
                    headers: {
                        'user-agent': 'DataBreachChecker-Backend/1.0',
                        'add-padding': 'true'
                    }
                }, 10000);
                lastErr = null;
                break;
            } catch (e) {
                lastErr = e;
                if (attempt < 3) await sleep(300 * attempt);
            }
        }

        if (!response && lastErr) {
            return res.status(502).json({ error: 'Erro ao contactar Pwned Passwords', details: lastErr.message });
        }

        if (!response.ok) {
            const errorText = await response.text();
            return res.status(response.status).json({ error: errorText || 'Erro ao consultar Pwned Passwords' });
        }

        const text = await response.text();
        let count = 0;
        for (const line of text.split(/\r?\n/)) {
            const [hashSuffix, c] = line.split(':');
            if (hashSuffix && hashSuffix.toUpperCase() === suffix) {
                count = parseInt((c || '0').trim(), 10) || 0;
                break;
            }
        }

        const payload = { pwned: count > 0, count };
        setCache(cacheKey, { status: 200, data: payload });
        return res.json(payload);
    } catch (error) {
        return res.status(500).json({ error: 'Erro interno do servidor', details: error.message });
    }
});

// Endpoint principal: Verificar email por vazamentos
app.get('/api/hibp/check/:email', async (req, res) => {
    const { email } = req.params;
    const clientIP = getClientIP(req);
    
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
