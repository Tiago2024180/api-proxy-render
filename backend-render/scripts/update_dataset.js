const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');

const HIBP_API_KEY = process.env.HIBP_API_KEY;
if (!HIBP_API_KEY) {
  console.error('HIBP_API_KEY not configured in environment. Exiting.');
  process.exit(1);
}

const outDir = path.join(__dirname, '..', 'datasets');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

async function fetchBreaches() {
  const url = 'https://haveibeenpwned.com/api/v3/breaches';
  console.log('Fetching breaches from HIBP...');
  const res = await fetch(url, { headers: { 'hibp-api-key': HIBP_API_KEY, 'user-agent': 'Dataset-Updater/1.0' } });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HIBP responded ${res.status}: ${text}`);
  }
  return res.json();
}

async function run() {
  try {
    const breaches = await fetchBreaches();
    const now = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `breaches-${now}.json`;
    const filepath = path.join(outDir, filename);
    fs.writeFileSync(filepath, JSON.stringify(breaches, null, 2));
    fs.writeFileSync(path.join(outDir, 'latest.json'), JSON.stringify({ generated_at: new Date().toISOString(), file: filename }, null, 2));
    console.log('Wrote dataset to', filepath);
    console.log(filepath);
  } catch (err) {
    console.error('Failed to update dataset:', err.message);
    process.exit(2);
  }
}

run();
