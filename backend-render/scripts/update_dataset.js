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

function readJsonIfExists(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function indexByName(breaches) {
  const m = new Map();
  if (!Array.isArray(breaches)) return m;
  for (const b of breaches) {
    if (b && typeof b.Name === 'string') m.set(b.Name, b);
  }
  return m;
}

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
    const prevPath = path.join(outDir, 'breaches-latest.json');
    const prevBreaches = readJsonIfExists(prevPath) || [];

    const breaches = await fetchBreaches();
    const now = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `breaches-${now}.json`;
    const filepath = path.join(outDir, filename);
    fs.writeFileSync(filepath, JSON.stringify(breaches, null, 2));

    // Stable "latest" dataset file for diffing / consumers
    fs.writeFileSync(prevPath, JSON.stringify(breaches, null, 2));

    // Compute newly added breaches since previous snapshot
    const prevIndex = indexByName(prevBreaches);
    const currIndex = indexByName(breaches);
    const added = [];
    for (const [name, breach] of currIndex.entries()) {
      if (!prevIndex.has(name)) added.push(breach);
    }

    fs.writeFileSync(
      path.join(outDir, 'new-breaches.json'),
      JSON.stringify({ generated_at: new Date().toISOString(), addedCount: added.length, added }, null, 2)
    );

    fs.writeFileSync(
      path.join(outDir, 'latest.json'),
      JSON.stringify(
        {
          generated_at: new Date().toISOString(),
          file: filename,
          totalBreaches: Array.isArray(breaches) ? breaches.length : 0,
          addedSinceLast: added.length
        },
        null,
        2
      )
    );
    console.log('Wrote dataset to', filepath);
    console.log(filepath);
  } catch (err) {
    console.error('Failed to update dataset:', err.message);
    process.exit(2);
  }
}

run();
