require('dotenv').config();
const express = require('express');
const https = require('https');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const FormData = require('form-data');
const cookieParser = require('cookie-parser');
const security = require('./security');
const crypto = require('crypto');

const app = express();
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const CLIENT_API_KEY = process.env.CLIENT_API_KEY || 'local-dev-client-key-change-before-production-2026';
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'local-dev-admin-key-change-before-production-2026';
const SESSION_SECRET = process.env.SESSION_SECRET || 'local-dev-cookie-secret-change-before-production-2026';
const VALID_LICENSES = new Set((process.env.VALID_LICENSE_KEYS || 'dev-license-change-me').split(',').map(v => v.trim()).filter(Boolean));
const PHP_LICENSE_VERIFY_URL = process.env.PHP_LICENSE_VERIFY_URL || '';
const FEATURE_API_KEY = process.env.FEATURE_API_KEY || 'local-dev-feature-key-change-before-production-2026';
if (IS_PRODUCTION && (!process.env.CLIENT_API_KEY || !process.env.ADMIN_API_KEY || !process.env.SESSION_SECRET || !process.env.HMAC_SALT || !process.env.PHP_LICENSE_VERIFY_URL)) {
    throw new Error('Production requires CLIENT_API_KEY, ADMIN_API_KEY, SESSION_SECRET, HMAC_SALT, and PHP_LICENSE_VERIFY_URL');
}
app.disable('x-powered-by');

// Request logging middleware - log ALL requests
app.use((req, res, next) => {
    console.log(`> ${req.method} ${req.url} from ${req.ip}`);
    next();
});

app.use(express.json({ limit: '128kb', strict: true }));
app.use(cookieParser(SESSION_SECRET));
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');if(IS_PRODUCTION)res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains');next();});

const requestBuckets = new Map();
function rateLimit(limit, windowMs) { return (req,res,next)=>{ const key=`${req.ip}|${req.path}`; const now=Date.now(); let b=requestBuckets.get(key); if(!b||b.reset<=now)b={count:0,reset:now+windowMs}; b.count++; requestBuckets.set(key,b); res.setHeader('RateLimit-Remaining',String(Math.max(0,limit-b.count))); if(b.count>limit)return res.status(429).json({success:false,error:'Too many requests'}); next(); }; }
setInterval(()=>{const now=Date.now();for(const [k,b] of requestBuckets)if(b.reset<=now)requestBuckets.delete(k);},60000).unref();
function safeEqual(a,b){const aa=Buffer.from(String(a||''));const bb=Buffer.from(String(b||''));return aa.length===bb.length&&crypto.timingSafeEqual(aa,bb);}
function requireClientKey(req,res,next){
    const publicApiPaths = new Set([
        '/api/auth/logout',
        '/api/stats/active-users',
        '/api/stats/auth',
        '/auth/logout',
        '/stats/active-users',
        '/stats/auth'
    ]);
    const originalPath = String(req.originalUrl || '').split('?')[0];
    if(publicApiPaths.has(req.path) || publicApiPaths.has(originalPath)) return next();
    if(!safeEqual(req.get('x-api-key'),CLIENT_API_KEY)){
        logToFile(`API_REJECT - Path: ${req.originalUrl || req.path} | IP: ${req.ip} | Reason: bad client key`);
        return res.status(401).json({success:false,error:'Unauthorized'});
    }
    next();
}
function requireAdminKey(req,res,next){if(!safeEqual(req.get('x-admin-key'),ADMIN_API_KEY))return res.status(403).json({success:false,error:'Forbidden'});next();}
app.use('/api', rateLimit(120,60000), requireClientKey);
app.use('/api/ban', requireAdminKey);
app.use('/api/integrity/register', requireAdminKey);

function expectedSessionSignature(token, session) {
    return crypto.createHmac('sha256', SESSION_SECRET)
        .update([token, session.hwid || '', session.buildId || '', session.licenseKey || ''].join('|'))
        .digest('hex');
}

function validatePlainClientSession(req, res) {
    const token = typeof req.body.token === 'string' ? req.body.token.slice(0, 128) : '';
    const signature = typeof req.body.signature === 'string' ? req.body.signature.slice(0, 128) : '';
    const hwid = typeof req.body.hwid === 'string' ? req.body.hwid.slice(0, 128) : '';
    const buildId = typeof req.body.buildId === 'string' ? req.body.buildId.slice(0, 128) : '';
    const sessions = loadJsonFile(CLIENT_SESSIONS_FILE, {});
    const session = sessions[token];
    if (!session || session.hwid !== hwid || session.buildId !== buildId) {
        res.status(403).json({ success: false, error: 'Session binding failed' });
        return null;
    }
    const expected = session.sessionSignature || expectedSessionSignature(token, session);
    if (!safeEqual(signature, expected)) {
        res.status(403).json({ success: false, error: 'Session signature failed' });
        return null;
    }
    return { token, signature, session, sessions };
}

function getOptionalPlainClientSession(req) {
    const token = typeof req.body.token === 'string' ? req.body.token.slice(0, 128) : '';
    const signature = typeof req.body.signature === 'string' ? req.body.signature.slice(0, 128) : '';
    const hwid = typeof req.body.hwid === 'string' ? req.body.hwid.slice(0, 128) : '';
    const buildId = typeof req.body.buildId === 'string' ? req.body.buildId.slice(0, 128) : '';
    if (!token || !signature || !hwid || !buildId) return null;
    const sessions = loadJsonFile(CLIENT_SESSIONS_FILE, {});
    const session = sessions[token];
    if (!session || session.hwid !== hwid || session.buildId !== buildId) return null;
    const expected = session.sessionSignature || expectedSessionSignature(token, session);
    if (!safeEqual(signature, expected)) return null;
    return { token, signature, session, sessions };
}

// Clean URL /dashboard - redirect to login if not authenticated
app.get('/dashboard', (req, res) => {
    const authCookie = req.signedCookies.crn_auth;
    if (!authCookie) {
        return res.redirect('/');
    }
    // Serve the dashboard file
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Block direct access to dashboard.html - redirect to clean URL or login
app.get('/dashboard.html', (req, res) => {
    const authCookie = req.signedCookies.crn_auth;
    if (!authCookie) {
        return res.redirect('/');
    }
    return res.redirect('/dashboard');
});

app.get('/dashboard/protection-data', (req, res) => {
    const authCookie = req.signedCookies.crn_auth;
    if (!authCookie) return res.status(401).json({ success: false, error: 'Unauthorized' });
    res.json({
        success: true,
        control: loadJsonFile(CONTROL_CONFIG_FILE, DEFAULT_CONTROL_CONFIG),
        protection: {
            recentEvents: readJsonLines(PROTECTION_LOG_FILE, 50),
            recentCrashes: readJsonLines(CRASH_REPORT_FILE, 20),
            recentCanaries: readJsonLines(CANARY_REPORT_FILE, 20),
            recentActions: readJsonLines(PROTECTION_ACTIONS_FILE, 20),
            recentSupportScreenshots: readJsonLines(SUPPORT_SCREENSHOT_LOG_FILE, 20)
        }
    });
});

app.get('/dashboard/protection-screenshot/:filename', (req, res) => {
    const authCookie = req.signedCookies.crn_auth;
    if (!authCookie) return res.status(401).send('Unauthorized');
    const filename = path.basename(String(req.params.filename || ''));
    const filePath = path.join(PROTECTION_SCREENSHOT_DIR, filename);
    if (!filename || !fs.existsSync(filePath)) return res.status(404).send('Not found');
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(filePath);
});

// Serve static files from 'public' folder (dashboard.html is handled above)
app.use(express.static(path.join(__dirname, 'public')));

// Configure multer for handling multipart uploads
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024, files: 1, fields: 24, fieldSize: 64 * 1024 } });

const PORT = Number.parseInt(process.env.PORT || '5555', 10);
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK_URL || '';
const CLEANUP_WEBHOOK = process.env.CLEANUP_WEBHOOK_URL || '';

// File paths
const BANNED_FILE = path.join(__dirname, 'banned.json');
const LOG_FILE = path.join(__dirname, 'access_logs.txt');
const HASHES_FILE = path.join(__dirname, 'hashes.json');
const PROTECTION_LOG_FILE = path.join(__dirname, 'protection_events.jsonl');
const PROTECTION_ACTIONS_FILE = path.join(__dirname, 'protection_actions.jsonl');
const CRASH_REPORT_FILE = path.join(__dirname, 'crash_reports.jsonl');
const CANARY_REPORT_FILE = path.join(__dirname, 'canary_events.jsonl');
const CONTROL_CONFIG_FILE = path.join(__dirname, 'control_config.json');
const CLIENT_SESSIONS_FILE = path.join(__dirname, 'client_sessions.json');
const SUPPORT_SCREENSHOT_DIR = path.join(__dirname, 'support_screenshots');
const SUPPORT_SCREENSHOT_LOG_FILE = path.join(__dirname, 'support_screenshots.jsonl');
const PROTECTION_SCREENSHOT_DIR = path.join(__dirname, 'protection_screenshots');

const DEFAULT_CONTROL_CONFIG = {
    currentVersion: '2.1.4',
    currentBuildId: 'dev-build-local',
    minimumBuildId: '',
    updateUrl: '/api/download/client',
    updateSha256: '',
    forceUpdate: false,
    maintenanceMode: false,
    killSwitch: {
        appDisabled: false,
        authDisabled: false,
        modulesDisabled: false,
        downloadsDisabled: false,
        reason: ''
    },
    revokedBuilds: [],
    revokedHwids: [],
    featureFlags: {
        protectionEnabled: true,
        memoryMonitor: true,
        antiHooking: true,
        canaryChecks: true,
        crashReporting: true,
        signedLocalConfig: true,
        riskScoring: true
    }
};

// Initialize banned.json if doesn't exist
if (!fs.existsSync(BANNED_FILE)) {
    fs.writeFileSync(BANNED_FILE, JSON.stringify({
        sids: [],
        ips: [],
        gpuHwids: [],
        cpuHwids: [],
        diskHwids: []
    }, null, 2));
}

// Load banned users
function loadBanned() {
    try {
        const data = fs.readFileSync(BANNED_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return { sids: [], ips: [], gpuHwids: [], cpuHwids: [], diskHwids: [] };
    }
}

// Save banned users
function saveBanned(banned) {
    fs.writeFileSync(BANNED_FILE, JSON.stringify(banned, null, 2));
}

// Load hashes database
function loadHashes() {
    try {
        const data = fs.readFileSync(HASHES_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return { setupMode: true, files: {} };
    }
}

// Save hashes database
function saveHashes(hashes) {
    fs.writeFileSync(HASHES_FILE, JSON.stringify(hashes, null, 2));
}

function loadJsonFile(filePath, fallback) {
    try {
        if (!fs.existsSync(filePath)) {
            fs.writeFileSync(filePath, JSON.stringify(fallback, null, 2));
            return JSON.parse(JSON.stringify(fallback));
        }
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch (err) {
        console.error(`Failed to load ${path.basename(filePath)}:`, err.message);
        return JSON.parse(JSON.stringify(fallback));
    }
}

function saveJsonFile(filePath, value) {
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function appendJsonLine(filePath, value) {
    fs.appendFileSync(filePath, `${JSON.stringify(value)}\n`, { encoding: 'utf8', mode: 0o600 });
}

function readJsonLines(filePath, limit = 50) {
    try {
        if (!fs.existsSync(filePath)) return [];
        const lines = fs.readFileSync(filePath, 'utf8').trim().split(/\r?\n/).filter(Boolean);
        return lines.slice(-limit).reverse().map(line => {
            try { return JSON.parse(line); } catch { return null; }
        }).filter(Boolean);
    } catch {
        return [];
    }
}

function cleanString(value, max) {
    return typeof value === 'string' ? value.slice(0, max) : '';
}

function safeScreenshotName(parts, extension = 'jpg') {
    const stem = parts
        .filter(Boolean)
        .join('_')
        .replace(/[^a-zA-Z0-9_-]/g, '')
        .slice(0, 96) || 'screenshot';
    return `${Date.now()}_${stem}.${extension}`;
}

function saveUploadedScreenshot(directory, file, parts) {
    if (!file || !file.buffer || file.buffer.length === 0) return '';
    if (!/^image\/(jpeg|png|webp)$/.test(String(file.mimetype || ''))) return '';
    if (!fs.existsSync(directory)) fs.mkdirSync(directory, { recursive: true });
    const extension = file.mimetype === 'image/png' ? 'png' : (file.mimetype === 'image/webp' ? 'webp' : 'jpg');
    const filename = safeScreenshotName(parts, extension);
    fs.writeFileSync(path.join(directory, filename), file.buffer, { mode: 0o600 });
    return filename;
}

function riskScoreForEvent(type) {
    const scores = {
        DEBUGGER_DETECTED: 50,
        INTEGRITY_VIOLATION: 100,
        MEMORY_PATCH: 90,
        API_HOOK: 80,
        CANARY_TRIGGERED: 70,
        CRASH_REPORT: 15,
        BAD_BUILD: 100
    };
    return scores[String(type || '').toUpperCase()] || 25;
}

function signText(text) {
    const privateKey = process.env.UPDATE_SIGNING_PRIVATE_KEY_PEM ||
        (process.env.UPDATE_SIGNING_PRIVATE_KEY_PEM_B64 ? Buffer.from(process.env.UPDATE_SIGNING_PRIVATE_KEY_PEM_B64, 'base64').toString('utf8') : '');
    if (privateKey) {
        return {
            algorithm: 'RSA-SHA256',
            signature: crypto.sign('sha256', Buffer.from(text), privateKey).toString('base64')
        };
    }
    return {
        algorithm: 'HMAC-SHA256-DEV',
        signature: crypto.createHmac('sha256', SESSION_SECRET).update(text).digest('hex')
    };
}

async function verifyPanelLicense(licenseKey, meta = {}) {
    if (PHP_LICENSE_VERIFY_URL) {
        try {
            const response = await axios.post(PHP_LICENSE_VERIFY_URL, {
                licenseKey,
                hwid: meta.hwid || '',
                buildId: meta.buildId || '',
                appVersion: meta.appVersion || ''
            }, {
                timeout: 4000,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Feature-API-Key': FEATURE_API_KEY
                },
                validateStatus: status => status >= 200 && status < 500
            });
            if (response.data && response.data.success === true) {
                return {
                    success: true,
                    username: String(response.data.username || 'member').slice(0, 128),
                    subscription: String(response.data.subscription || 'Standard').slice(0, 64),
                    expiry: Number.isSafeInteger(response.data.expiry) ? response.data.expiry : 0
                };
            }
            return { success: false, message: response.data?.message || 'License is not redeemed or active' };
        } catch (error) {
            console.error('PHP license verification error:', error.message);
            return { success: false, message: 'License verification service unavailable' };
        }
    }

    if (VALID_LICENSES.has(licenseKey)) return { success: true, username: 'member', subscription: 'Standard', expiry: 0 };
    return { success: false, message: 'Invalid license key' };
}

// Log to file
function logToFile(message) {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${message}\n`;
    fs.appendFileSync(LOG_FILE, logEntry);
}

// Send to Discord. When an alert includes a screenshot, send it as a Discord
// attachment so the embed can render the same image the admin panel stores.
async function sendDiscordWebhook(embed, attachment = null) {
    if (!DISCORD_WEBHOOK || DISCORD_WEBHOOK === "YOUR_DISCORD_WEBHOOK_HERE") {
        console.log('WARNING: Discord webhook not configured');
        return;
    }

    try {
        if (attachment?.buffer?.length) {
            const formData = new FormData();
            formData.append('payload_json', JSON.stringify({ embeds: [embed] }));
            formData.append('files[0]', attachment.buffer, {
                filename: attachment.filename || 'screenshot.jpg',
                contentType: attachment.contentType || 'image/jpeg'
            });
            await axios.post(DISCORD_WEBHOOK, formData, { headers: formData.getHeaders() });
            return;
        }
        await axios.post(DISCORD_WEBHOOK, { embeds: [embed] });
    } catch (error) {
        console.error('Discord webhook error:', error.message);
    }
}

// Send to Cleanup Discord Webhook
async function sendCleanupWebhook(embed) {
    if (!CLEANUP_WEBHOOK) return;
    try {
        await axios.post(CLEANUP_WEBHOOK, { embeds: [embed] });
    } catch (error) {
        console.error('Cleanup webhook error:', error.message);
    }
}

let activeUserCount = 0;

// ============================================================================
// INFO PIPE - Server-Sent Events for real-time progress & security alerts
// ============================================================================
const connectedClients = new Map(); // clientId -> response object

// Generate unique client ID
function generateClientId() {
    return `client_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// Broadcast to all connected clients
function broadcastToClients(eventType, data) {
    const message = JSON.stringify({ type: eventType, data, timestamp: Date.now() });
    connectedClients.forEach((res, clientId) => {
        try {
            res.write(`event: ${eventType}\n`);
            res.write(`data: ${message}\n\n`);
        } catch (err) {
            console.log(`> Client disconnected: ${clientId}`);
            connectedClients.delete(clientId);
        }
    });
}

// Send to specific client
function sendToClient(clientId, eventType, data) {
    const client = connectedClients.get(clientId);
    if (client) {
        const message = JSON.stringify({ type: eventType, data, timestamp: Date.now() });
        try {
            client.write(`event: ${eventType}\n`);
            client.write(`data: ${message}\n\n`);
        } catch (err) {
            connectedClients.delete(clientId);
        }
    }
}

// Helper: Send progress update (forwards to CLEANUP_WEBHOOK)
async function sendProgress(clientId, progress, phase, message) {
    const data = { progress, phase, message };
    if (clientId) {
        sendToClient(clientId, 'progress', data);
    } else {
        broadcastToClients('progress', data);
    }

    // Forward to Discord (info/progress webhook)
    let color = 0x3498DB; // Blue
    if (progress >= 100) color = 0x2ECC71; // Green
    else if (progress >= 75) color = 0xF1C40F; // Yellow
    else if (progress >= 50) color = 0xE67E22; // Orange

    try {
        await axios.post(CLEANUP_WEBHOOK, {
            embeds: [{
                title: `📊 Progress Update: ${progress}%`,
                color: color,
                fields: [
                    { name: 'Phase', value: phase || 'Unknown', inline: true },
                    { name: 'Progress', value: `${progress}%`, inline: true },
                    { name: 'Message', value: message || 'No message', inline: false }
                ],
                timestamp: new Date().toISOString()
            }]
        });
    } catch (err) {
        console.error('Progress webhook error:', err.message);
    }
}

// Helper: Send security alert (forwards to DISCORD_WEBHOOK)
async function sendSecurityAlert(alertType, details) {
    broadcastToClients('security_alert', { alertType, details });

    // Forward to Discord (security webhook)
    let color = 0xFF0000; // Red default
    let emoji = '🚨';

    if (alertType === 'warning') { color = 0xFFFF00; emoji = '⚠️'; }
    else if (alertType === 'critical') { color = 0x8B0000; emoji = '🔴'; }
    else if (alertType === 'info') { color = 0x0099FF; emoji = 'ℹ️'; }

    try {
        await axios.post(DISCORD_WEBHOOK, {
            embeds: [{
                title: `${emoji} Security Alert: ${alertType.toUpperCase()}`,
                color: color,
                fields: Object.entries(details || {}).map(([key, value]) => ({
                    name: key,
                    value: String(value),
                    inline: true
                })),
                timestamp: new Date().toISOString()
            }]
        });
    } catch (err) {
        console.error('Security webhook error:', err.message);
    }
}

// ENDPOINT: SSE connection for info pipe
app.get('/api/info-pipe', (req, res) => {
    const clientId = req.query.clientId || generateClientId();

    // Set SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();

    // Send connected event with client ID
    res.write(`event: connected\n`);
    res.write(`data: ${JSON.stringify({ clientId, timestamp: Date.now() })}\n\n`);

    // Store client connection
    connectedClients.set(clientId, res);
    console.log(`> Info pipe connected: ${clientId} (${connectedClients.size} total)`);

    // Heartbeat to keep connection alive
    const heartbeat = setInterval(() => {
        try {
            res.write(`event: heartbeat\n`);
            res.write(`data: ${JSON.stringify({ timestamp: Date.now() })}\n\n`);
        } catch (err) {
            clearInterval(heartbeat);
        }
    }, 30000);

    // Cleanup on disconnect
    req.on('close', () => {
        clearInterval(heartbeat);
        connectedClients.delete(clientId);
        console.log(`> Info pipe disconnected: ${clientId} (${connectedClients.size} remaining)`);
    });
});

// ENDPOINT: Send progress update via POST
app.post('/api/info-pipe/progress', (req, res) => {
    const { clientId, progress, phase, message } = req.body;
    sendProgress(clientId || null, progress, phase, message);
    console.log(`> Progress: ${phase} - ${progress}% - ${message}`);
    res.json({ success: true });
});

// ENDPOINT: Send security alert via POST
app.post('/api/info-pipe/security-alert', (req, res) => {
    const { alertType, details } = req.body;
    sendSecurityAlert(alertType, details);
    console.log(`> Security Alert: ${alertType}`);
    res.json({ success: true });
});

// ENDPOINT: Get connected clients count
app.get('/api/info-pipe/status', (req, res) => {
    res.json({
        connectedClients: connectedClients.size,
        clientIds: Array.from(connectedClients.keys())
    });
});

// ENDPOINT: Custom auth placeholder
app.post('/api/auth/custom-login', async (req, res) => {
    const { licenseKey } = req.body;
    const clean = (value, max) => typeof value === 'string' ? value.slice(0, max) : '';

    if (!licenseKey) {
        return res.json({
            success: false,
            message: 'License key is required'
        });
    }

    try {
        const isClientApp = req.headers['x-client-type'] === 'app' || req.headers['user-agent']?.includes('BajpasClient');
        const loginType = isClientApp ? 'CLIENT_APP' : 'WEB';
        const hwid = clean(req.body.hwid, 128);
        const buildId = clean(req.body.buildId, 128);
        const appVersion = clean(req.body.appVersion, 32);
        const pcName = clean(req.body.pcName, 128);
        const machineUser = clean(req.body.machineUser, 128);
        const licenseCheck = await verifyPanelLicense(licenseKey, { hwid, buildId, appVersion });
        if (!licenseCheck.success) {
            return res.json({ success: false, message: licenseCheck.message || 'License verification failed' });
        }
        const username = licenseCheck.username || 'member';
        const subscription = licenseCheck.subscription || 'Standard';
        const expiry = licenseCheck.expiry || 0;
        const control = loadJsonFile(CONTROL_CONFIG_FILE, DEFAULT_CONTROL_CONFIG);

        if ((hwid && control.revokedHwids?.includes(hwid)) || (buildId && control.revokedBuilds?.includes(buildId))) {
            return res.status(403).json({ success: false, message: 'Client build or machine is revoked' });
        }

        activeUserCount = Math.max(activeUserCount, 1);
        console.log(`> ${loginType} custom login accepted - User: ${username}`);
        logToFile(`${loginType}_CUSTOM_LOGIN - User: ${username} | Build: ${buildId || 'unknown'} | HWID: ${hwid || 'unknown'} | IP: ${req.ip}`);

        const authToken = crypto.randomBytes(32).toString('hex');
        const sessionBinding = [authToken, hwid, buildId, licenseKey].join('|');
        const sessionSignature = crypto.createHmac('sha256', SESSION_SECRET).update(sessionBinding).digest('hex');
        const sessions = loadJsonFile(CLIENT_SESSIONS_FILE, {});
        sessions[authToken] = {
            username,
            subscription,
            expiry,
            licenseKey,
            sessionSignature,
            hwid,
            buildId,
            appVersion,
            pcName,
            machineUser,
            sourceIp: req.ip,
            createdAt: new Date().toISOString(),
            lastSeenAt: new Date().toISOString()
        };
        saveJsonFile(CLIENT_SESSIONS_FILE, sessions);

        res.cookie('crn_auth', authToken, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: 'strict',
            signed: true,
            maxAge: 24 * 60 * 60 * 1000
        });

        res.json({
            success: true,
            token: authToken,
            sessionSignature,
            username,
            subscription,
            expiry,
            buildId: control.currentBuildId,
            featureFlags: control.featureFlags,
            killSwitch: control.killSwitch || DEFAULT_CONTROL_CONFIG.killSwitch
        });
    } catch (error) {
        console.error('Custom auth error:', error.message);
        logToFile(`WEB_CUSTOM_LOGIN_ERROR - Error: ${error.message} | IP: ${req.ip}`);

        res.json({
            success: false,
            message: 'Custom authentication failed. Please try again.'
        });
    }
});

// ENDPOINT: Logout - clear auth cookie
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('crn_auth', { httpOnly:true, secure:IS_PRODUCTION, sameSite:'strict', signed:true });
    res.json({ success: true });
});

app.post('/api/client/config', (req, res) => {
    const control = loadJsonFile(CONTROL_CONFIG_FILE, DEFAULT_CONTROL_CONFIG);
    const hwid = typeof req.body.hwid === 'string' ? req.body.hwid.slice(0, 128) : '';
    const buildId = typeof req.body.buildId === 'string' ? req.body.buildId.slice(0, 128) : '';
    res.json({
        success: true,
        serverTime: new Date().toISOString(),
        revoked: Boolean((hwid && control.revokedHwids?.includes(hwid)) || (buildId && control.revokedBuilds?.includes(buildId))),
        maintenanceMode: Boolean(control.maintenanceMode),
        currentVersion: control.currentVersion,
        currentBuildId: control.currentBuildId,
        forceUpdate: Boolean(control.forceUpdate),
        featureFlags: control.featureFlags || DEFAULT_CONTROL_CONFIG.featureFlags,
        killSwitch: control.killSwitch || DEFAULT_CONTROL_CONFIG.killSwitch
    });
});

app.post('/api/update/check', (req, res) => {
    const control = loadJsonFile(CONTROL_CONFIG_FILE, DEFAULT_CONTROL_CONFIG);
    const buildId = typeof req.body.buildId === 'string' ? req.body.buildId.slice(0, 128) : '';
    const hwid = typeof req.body.hwid === 'string' ? req.body.hwid.slice(0, 128) : '';
    const manifest = {
        currentVersion: control.currentVersion,
        currentBuildId: control.currentBuildId,
        updateUrl: control.updateUrl,
        updateSha256: control.updateSha256,
        forceUpdate: Boolean(control.forceUpdate),
        killSwitch: control.killSwitch || DEFAULT_CONTROL_CONFIG.killSwitch,
        revoked: Boolean((hwid && control.revokedHwids?.includes(hwid)) || (buildId && control.revokedBuilds?.includes(buildId))),
        issuedAt: new Date().toISOString()
    };
    const canonical = JSON.stringify(manifest);
    res.json({ success: true, manifest, signed: signText(canonical) });
});

app.post('/api/session/heartbeat', (req, res) => {
    const validated = validatePlainClientSession(req, res);
    if (!validated) return;
    const { session, sessions } = validated;
    const control = loadJsonFile(CONTROL_CONFIG_FILE, DEFAULT_CONTROL_CONFIG);
    const killSwitch = control.killSwitch || DEFAULT_CONTROL_CONFIG.killSwitch;
    const revoked = Boolean((session.hwid && control.revokedHwids?.includes(session.hwid)) || (session.buildId && control.revokedBuilds?.includes(session.buildId)));
    const globalKill = Boolean(killSwitch.appDisabled || control.maintenanceMode || revoked);
    session.lastSeenAt = new Date().toISOString();
    session.sourceIp = req.ip;
    const response = {
        success: true,
        kill: Boolean(session.killed || globalKill),
        killReason: session.killReason || killSwitch.reason || (revoked ? 'This build or machine was revoked.' : ''),
        screenshotRequested: Boolean(session.screenshotRequested),
        screenshotRequestId: session.screenshotRequestId || '',
        killSwitch,
        maintenanceMode: Boolean(control.maintenanceMode),
        revoked
    };
    if (session.screenshotRequested) {
        session.screenshotRequested = false;
        session.screenshotRequestDeliveredAt = new Date().toISOString();
    }
    saveJsonFile(CLIENT_SESSIONS_FILE, sessions);
    res.json(response);
});

app.post('/api/support/screenshot', upload.single('screenshot'), (req, res) => {
    req.body.hwid = typeof req.body.hwid === 'string' ? req.body.hwid : '';
    req.body.buildId = typeof req.body.buildId === 'string' ? req.body.buildId : '';
    const validated = validatePlainClientSession(req, res);
    if (!validated) return;
    const { session } = validated;
    const requestId = typeof req.body.requestId === 'string' ? req.body.requestId.slice(0, 64) : '';
    const consent = req.body.consent === 'accepted' ? 'accepted' : 'declined';

    let filename = '';
    if (consent === 'accepted' && req.file && req.file.buffer && req.file.buffer.length > 0) {
        if (!fs.existsSync(SUPPORT_SCREENSHOT_DIR)) fs.mkdirSync(SUPPORT_SCREENSHOT_DIR, { recursive: true });
        filename = `${Date.now()}_${String(session.hwid || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32)}_${requestId || 'request'}.jpg`;
        fs.writeFileSync(path.join(SUPPORT_SCREENSHOT_DIR, filename), req.file.buffer, { mode: 0o600 });
    }

    const processId = Number.parseInt(req.body.processId, 10);
    const clientTimestamp = Number.parseInt(req.body.timestamp, 10);
    const event = {
        receivedAt: new Date().toISOString(),
        requestId,
        consent,
        filename,
        username: session.username || '',
        hwid: session.hwid || '',
        buildId: session.buildId || '',
        sourceIp: req.ip
    };
    appendJsonLine(SUPPORT_SCREENSHOT_LOG_FILE, event);
    broadcastToClients('support_screenshot', event);
    res.json({ success: true });
});

// ENDPOINT: Get active users count from custom auth session state
app.get('/api/stats/active-users', async (req, res) => {
    res.json({
        success: true,
        count: activeUserCount
    });
});

// ENDPOINT: Get custom auth app statistics
app.get('/api/stats/auth', async (req, res) => {
    res.json({
        success: true,
        stats: {
            numUsers: '1',
            numKeys: '0',
            numOnlineUsers: String(activeUserCount),
            version: '1.0',
            customerPanelLink: ''
        }
    });
});

// ENDPOINT: Check if user is banned (called on app startup)
app.post('/api/check', async (req, res) => {
    // Increment active user count
    activeUserCount++;

    setTimeout(() => {
        activeUserCount = Math.max(0, activeUserCount - 1);
    }, 300000); // Decrease after 5 minutes
    const { sid, ip, gpuHwid, cpuHwid, diskHwid, username, computerName } = req.body;

    // Console output with checkmark
    console.log(`> App opened - ${username}@${computerName} - ${ip} - ${new Date().toLocaleTimeString()}`);

    const banned = loadBanned();

    // Check if any identifier is banned
    const isBanned =
        banned.sids.includes(sid) ||
        banned.ips.includes(ip) ||
        banned.gpuHwids.includes(gpuHwid) ||
        banned.cpuHwids.includes(cpuHwid) ||
        banned.diskHwids.includes(diskHwid);

    if (isBanned) {
        // Log ban attempt
        const banLog = `BAN_ATTEMPT - User: ${username} | PC: ${computerName} | IP: ${ip} | SID: ${sid}`;
        logToFile(banLog);
        console.log(`> BLOCKED - Banned user: ${username} - ${ip}`);

        // Send Discord alert
        await sendDiscordWebhook({
            title: 'Access Blocked - Banned User',
            color: 0xFF0000,
            fields: [
                { name: 'Username', value: username || 'Unknown', inline: true },
                { name: 'Computer', value: computerName || 'Unknown', inline: true },
                { name: 'IP Address', value: ip || 'Unknown', inline: true },
                { name: 'SID', value: sid || 'Unknown', inline: false },
                { name: 'GPU HWID', value: gpuHwid || 'Unknown', inline: true },
                { name: 'CPU HWID', value: cpuHwid || 'Unknown', inline: true },
                { name: 'Disk HWID', value: diskHwid || 'Unknown', inline: true },
            ],
            timestamp: new Date().toISOString()
        });

        return res.json({ allowed: false, reason: 'User is banned' });
    }

    // Log successful access
    const accessLog = `ACCESS_GRANTED - User: ${username} | PC: ${computerName} | IP: ${ip} | SID: ${sid}`;
    logToFile(accessLog);

    // Send Discord notification
    await sendDiscordWebhook({
        title: 'Access Granted',
        color: 0x00FF00,
        fields: [
            { name: 'Username', value: username || 'Unknown', inline: true },
            { name: 'Computer', value: computerName || 'Unknown', inline: true },
            { name: 'IP Address', value: ip || 'Unknown', inline: true },
            { name: 'SID', value: sid || 'Unknown', inline: false },
            { name: 'GPU HWID', value: gpuHwid || 'Unknown', inline: true },
            { name: 'CPU HWID', value: cpuHwid || 'Unknown', inline: true },
            { name: 'Disk HWID', value: diskHwid || 'Unknown', inline: true },
        ],
        timestamp: new Date().toISOString()
    });

    res.json({ allowed: true });
});

// ENDPOINT: Ban a user
app.post('/api/ban', (req, res) => {
    const { sid, ip, gpuHwid, cpuHwid, diskHwid, reason } = req.body;

    const banned = loadBanned();

    if (sid && !banned.sids.includes(sid)) banned.sids.push(sid);
    if (ip && !banned.ips.includes(ip)) banned.ips.push(ip);
    if (gpuHwid && !banned.gpuHwids.includes(gpuHwid)) banned.gpuHwids.push(gpuHwid);
    if (cpuHwid && !banned.cpuHwids.includes(cpuHwid)) banned.cpuHwids.push(cpuHwid);
    if (diskHwid && !banned.diskHwids.includes(diskHwid)) banned.diskHwids.push(diskHwid);

    saveBanned(banned);

    logToFile(`USER_BANNED - Reason: ${reason || 'No reason'} | SID: ${sid} | IP: ${ip}`);
    console.log(`> User banned - SID: ${sid} - IP: ${ip}`);

    res.json({ success: true, message: 'User banned successfully' });
});

// ENDPOINT: General logging
app.post('/api/log', async (req, res) => {
    const { type, message, details } = req.body;

    console.log(`> Log: ${type} - ${message}`);
    logToFile(`LOG - Type: ${type} | Message: ${message}`);

    let color = 0x0099FF;
    if (type.includes('DEBUG') || type.includes('DETECTION')) color = 0xFFFF00;
    if (type.includes('BAN')) color = 0xFF0000;

    await sendDiscordWebhook({
        title: type,
        description: message,
        color: color,
        fields: details ? Object.entries(details).map(([key, value]) => ({
            name: key,
            value: String(value),
            inline: true
        })) : [],
        timestamp: new Date().toISOString()
    });

    res.json({ success: true });
});

// ENDPOINT: Download DLLs for phase 3 update
app.get('/api/download/cleaning.dll', (req, res) => {
    // We can just create empty files for testing or real dlls if they exist
    const filePath = path.join(__dirname, 'public', 'cleaning.dll');
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).send('File not found');
    }
});

app.get('/api/download/dih.dll', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'destuction.dll');
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).send('File not found');
    }
});

// ENDPOINT: Debugger alert with screenshot
app.post('/api/security/debugger-alert', upload.single('screenshot'), async (req, res) => {
    try {
        const { detectionMethod, hwid, username, pcName, publicIP, timestamp } = req.body;
        const screenshot = req.file; // The uploaded JPEG file

        console.log(`> DEBUGGER DETECTED - ${username}@${pcName} - Method: ${detectionMethod}`);
        logToFile(`DEBUGGER_DETECTED - User: ${username} | PC: ${pcName} | IP: ${publicIP} | Method: ${detectionMethod}`);

        // Create Discord embed with screenshot
        const formData = new FormData();

        // Build embed JSON
        const embed = {
            title: '🚨 DEBUGGER DETECTED',
            description: 'Someone is debugging the scanner!',
            color: 0xFF0000, // Red
            fields: [
                { name: 'Detection Method', value: detectionMethod || 'Unknown', inline: true },
                { name: 'HWID', value: hwid || 'Unknown', inline: true },
                { name: 'Username', value: username || 'Unknown', inline: true },
                { name: 'PC Name', value: pcName || 'Unknown', inline: true },
                { name: 'Public IP', value: publicIP || 'Unknown', inline: true },
                { name: 'Timestamp', value: timestamp ? new Date(parseInt(timestamp) * 1000).toLocaleString() : new Date().toLocaleString(), inline: true }
            ],
            footer: {
                text: 'Traceitt Scanner Security • ' + new Date().toLocaleDateString() + ' ' + new Date().toLocaleTimeString()
            },
            timestamp: new Date().toISOString()
        };

        // If screenshot exists, attach it
        if (screenshot && screenshot.buffer) {
            embed.image = { url: 'attachment://screenshot.jpg' };
            formData.append('file', screenshot.buffer, {
                filename: 'screenshot.jpg',
                contentType: 'image/jpeg'
            });
        }

        // Add embed to form data
        formData.append('payload_json', JSON.stringify({
            content: '@everyone',
            embeds: [embed]
        }));

        // Send to Discord webhook
        await axios.post(DISCORD_WEBHOOK, formData, {
            headers: formData.getHeaders()
        });

        console.log(`> Screenshot sent to Discord - ${username}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Debugger alert error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ENDPOINT: Encrypted debugger alert with AES-GCM screenshot (new secure method)
app.post('/api/security/encrypted-alert', upload.single('screenshot'), async (req, res) => {
    try {
        const { detectionMethod, hwid, username, pcName, timestamp, encrypted, screenshotHash } = req.body;
        const screenshotFile = req.file;

        console.log(`> [SECURE] DEBUGGER DETECTED - ${username}@${pcName} - Method: ${detectionMethod}`);
        console.log(`> [SECURE] Encrypted: ${encrypted}, Has file: ${!!screenshotFile}`);
        logToFile(`SECURE_DEBUGGER_DETECTED - User: ${username} | PC: ${pcName} | Method: ${detectionMethod}`);

        // If we only received a hash (fallback mode)
        if (screenshotHash && !screenshotFile) {
            console.log(`> [SECURE] Screenshot hash only: ${screenshotHash.substring(0, 16)}...`);

            await sendDiscordWebhook({
                title: '🔐 DEBUGGER DETECTED (Secure)',
                description: 'Screenshot capture was blocked - hash only',
                color: 0xFF6600, // Orange - indicates partial capture
                fields: [
                    { name: 'Detection Method', value: detectionMethod || 'Unknown', inline: true },
                    { name: 'HWID', value: hwid || 'Unknown', inline: true },
                    { name: 'Username', value: username || 'Unknown', inline: true },
                    { name: 'PC Name', value: pcName || 'Unknown', inline: true },
                    { name: 'Screenshot Hash', value: screenshotHash ? screenshotHash.substring(0, 32) + '...' : 'None', inline: false },
                    { name: 'Status', value: '⚠️ Screenshot hooks detected - only hash available', inline: false }
                ],
                timestamp: new Date().toISOString()
            });

            return res.json({ success: true, mode: 'hash_only' });
        }

        // If we received encrypted screenshot, decrypt it
        if (screenshotFile && screenshotFile.buffer && encrypted === 'true') {
            console.log(`> [SECURE] Decrypting screenshot (${screenshotFile.buffer.length} bytes)...`);

            // Derive the same key the client used
            const license = hwid; // Client uses license as session token
            const combined = `${license}|${hwid}|ScreenshotKey2025`;
            const key = crypto.createHash('sha256').update(combined).digest();

            // Parse encrypted data: [IV (12)] [AuthTag (16)] [Ciphertext (rest)]
            const encData = screenshotFile.buffer;

            if (encData.length < 28) {
                console.log(`> [SECURE] Encrypted data too short: ${encData.length} bytes`);
                return res.status(400).json({ success: false, error: 'Invalid encrypted data' });
            }

            const iv = encData.slice(0, 12);
            const authTag = encData.slice(12, 28);
            const ciphertext = encData.slice(28);

            try {
                // Decrypt using AES-256-GCM
                const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
                decipher.setAuthTag(authTag);

                const decrypted = Buffer.concat([
                    decipher.update(ciphertext),
                    decipher.final()
                ]);

                console.log(`> [SECURE] Decrypted screenshot: ${decrypted.length} bytes`);

                // Send to Discord with decrypted image
                const formData = new FormData();

                const embed = {
                    title: '🔐🚨 DEBUGGER DETECTED (Secure)',
                    description: 'AES-256-GCM encrypted screenshot captured via DXGI',
                    color: 0xFF0000,
                    fields: [
                        { name: 'Detection Method', value: detectionMethod || 'Unknown', inline: true },
                        { name: 'HWID', value: hwid || 'Unknown', inline: true },
                        { name: 'Username', value: username || 'Unknown', inline: true },
                        { name: 'PC Name', value: pcName || 'Unknown', inline: true },
                        { name: 'Capture Method', value: '🛡️ DXGI (Secure)', inline: true },
                        { name: 'Encryption', value: '🔒 AES-256-GCM', inline: true }
                    ],
                    image: { url: 'attachment://screenshot.jpg' },
                    footer: { text: 'Secure Protection v2.0' },
                    timestamp: new Date().toISOString()
                };

                formData.append('file', decrypted, {
                    filename: 'screenshot.jpg',
                    contentType: 'image/jpeg'
                });

                formData.append('payload_json', JSON.stringify({
                    content: '@everyone',
                    embeds: [embed]
                }));

                await axios.post(DISCORD_WEBHOOK, formData, {
                    headers: formData.getHeaders()
                });

                console.log(`> [SECURE] Decrypted screenshot sent to Discord`);
                return res.json({ success: true, mode: 'encrypted' });

            } catch (decryptError) {
                console.error(`> [SECURE] Decryption failed: ${decryptError.message}`);

                // Send alert without screenshot
                await sendDiscordWebhook({
                    title: '🔐⚠️ DEBUGGER DETECTED (Decryption Failed)',
                    description: 'Could not decrypt screenshot - possible tampering',
                    color: 0xFF0000,
                    fields: [
                        { name: 'Detection Method', value: detectionMethod || 'Unknown', inline: true },
                        { name: 'HWID', value: hwid || 'Unknown', inline: true },
                        { name: 'Username', value: username || 'Unknown', inline: true },
                        { name: 'PC Name', value: pcName || 'Unknown', inline: true },
                        { name: 'Error', value: decryptError.message, inline: false }
                    ],
                    timestamp: new Date().toISOString()
                });

                return res.json({ success: true, mode: 'decryption_failed' });
            }
        }

        // Fallback: unencrypted screenshot (legacy)
        if (screenshotFile && encrypted !== 'true') {
            console.log(`> [SECURE] Unencrypted screenshot received (legacy mode)`);

            const formData = new FormData();

            const embed = {
                title: '🚨 DEBUGGER DETECTED',
                description: 'Legacy unencrypted capture',
                color: 0xFF0000,
                fields: [
                    { name: 'Detection Method', value: detectionMethod || 'Unknown', inline: true },
                    { name: 'HWID', value: hwid || 'Unknown', inline: true },
                    { name: 'Username', value: username || 'Unknown', inline: true },
                    { name: 'PC Name', value: pcName || 'Unknown', inline: true }
                ],
                image: { url: 'attachment://screenshot.jpg' },
                timestamp: new Date().toISOString()
            };

            formData.append('file', screenshotFile.buffer, {
                filename: 'screenshot.jpg',
                contentType: 'image/jpeg'
            });

            formData.append('payload_json', JSON.stringify({
                content: '@everyone',
                embeds: [embed]
            }));

            await axios.post(DISCORD_WEBHOOK, formData, {
                headers: formData.getHeaders()
            });

            return res.json({ success: true, mode: 'legacy' });
        }

        // No screenshot at all
        await sendDiscordWebhook({
            title: '🔐 DEBUGGER DETECTED (No Screenshot)',
            color: 0xFF6600,
            fields: [
                { name: 'Detection Method', value: detectionMethod || 'Unknown', inline: true },
                { name: 'HWID', value: hwid || 'Unknown', inline: true },
                { name: 'Username', value: username || 'Unknown', inline: true },
                { name: 'PC Name', value: pcName || 'Unknown', inline: true }
            ],
            timestamp: new Date().toISOString()
        });

        res.json({ success: true, mode: 'no_screenshot' });

    } catch (error) {
        console.error('Encrypted alert error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================================================
// INTEGRITY CHECKING ENDPOINTS - SERVER-SIDE HASH VERIFICATION
// ============================================================================

// ENDPOINT: Verify file integrity (called by client every 3 seconds)
app.post('/api/integrity/verify', async (req, res) => {
    try {
        const { fileName, fileHash, hwid, username, pcName, ip, license } = req.body;

        if (!fileName || !fileHash) {
            return res.status(400).json({
                valid: false,
                error: 'Missing fileName or fileHash'
            });
        }

        const hashDB = loadHashes();

        // SETUP MODE: Accept any hash and store it
        if (hashDB.setupMode === true) {
            console.log(`> [SETUP MODE] Registering hash for ${fileName}: ${fileHash.substring(0, 16)}...`);

            if (!hashDB.files) hashDB.files = {};

            hashDB.files[fileName] = {
                hash: fileHash,
                lastUpdated: new Date().toISOString(),
                notes: `Hash registered from ${username}@${pcName}`
            };

            saveHashes(hashDB);

            return res.json({
                valid: true,
                setupMode: true,
                message: 'Hash registered - set setupMode to false in hashes.json to enable verification'
            });
        }

        // PRODUCTION MODE: Verify hash against database
        const expectedFile = hashDB.files[fileName];

        if (!expectedFile || !expectedFile.hash) {
            console.log(`> [WARNING] No hash configured for ${fileName}`);
            return res.json({
                valid: false,
                error: 'File not registered in hash database',
                setupMode: false
            });
        }

        const isValid = (fileHash.toLowerCase() === expectedFile.hash.toLowerCase());

        if (!isValid) {
            // TAMPERING DETECTED!
            console.log(`> [INTEGRITY VIOLATION] ${fileName} - ${username}@${pcName}`);
            console.log(`  Expected: ${expectedFile.hash.substring(0, 16)}...`);
            console.log(`  Got:      ${fileHash.substring(0, 16)}...`);

            logToFile(`INTEGRITY_VIOLATION - File: ${fileName} | User: ${username} | PC: ${pcName} | IP: ${ip}`);

            // Send Discord alert
            await sendDiscordWebhook({
                title: '🚨 FILE TAMPERING DETECTED',
                description: `**${fileName}** has been modified!`,
                color: 0xFF0000, // Red
                fields: [
                    { name: 'File', value: fileName, inline: true },
                    { name: 'Username', value: username || 'Unknown', inline: true },
                    { name: 'PC Name', value: pcName || 'Unknown', inline: true },
                    { name: 'IP Address', value: ip || 'Unknown', inline: false },
                    { name: 'HWID', value: hwid || 'Unknown', inline: true },
                    { name: 'License', value: license || 'Unknown', inline: true },
                    { name: 'Expected Hash', value: `\`${expectedFile.hash.substring(0, 32)}...\``, inline: false },
                    { name: 'Received Hash', value: `\`${fileHash.substring(0, 32)}...\``, inline: false },
                    { name: 'Timestamp', value: new Date().toLocaleString(), inline: true }
                ],
                footer: {
                    text: 'Integrity Violation • Auto-ban triggered'
                },
                timestamp: new Date().toISOString()
            });

            return res.json({
                valid: false,
                tampered: true,
                message: 'File integrity violation detected'
            });
        }

        // Hash is valid
        return res.json({
            valid: true,
            setupMode: false
        });

    } catch (error) {
        console.error('Integrity verification error:', error.message);
        res.status(500).json({
            valid: false,
            error: error.message
        });
    }
});

// ENDPOINT: Register hash (manual hash registration - for testing)
app.post('/api/integrity/register', (req, res) => {
    try {
        const { fileName, fileHash, notes } = req.body;

        if (!fileName || !fileHash) {
            return res.status(400).json({
                success: false,
                error: 'Missing fileName or fileHash'
            });
        }

        const hashDB = loadHashes();

        if (!hashDB.files) hashDB.files = {};

        hashDB.files[fileName] = {
            hash: fileHash,
            lastUpdated: new Date().toISOString(),
            notes: notes || 'Manually registered'
        };

        saveHashes(hashDB);

        console.log(`> Hash registered for ${fileName}: ${fileHash.substring(0, 16)}...`);

        res.json({
            success: true,
            message: `Hash registered for ${fileName}`
        });

    } catch (error) {
        console.error('Hash registration error:', error.message);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// ============================================================================
// CLEANUP MONITORING ENDPOINTS - Forwards to Discord webhook (no database)
// ============================================================================

// Append-only client protection telemetry. Authentication and rate limiting are
// applied globally to every /api route above.
app.post('/api/protection/event', upload.single('screenshot'), (req, res) => {
    req.body.token = cleanString(req.body.token || req.body.sessionToken, 128);
    req.body.signature = cleanString(req.body.signature || req.body.sessionSignature, 128);
    req.body.hwid = cleanString(req.body.hwid, 128);
    req.body.buildId = cleanString(req.body.buildId, 128);
    const validated = getOptionalPlainClientSession(req);
    const session = validated ? validated.session : {};
    const type = cleanString(req.body.type, 64).toUpperCase();
    const message = cleanString(req.body.message, 1024);

    if (!/^[A-Z0-9_]+$/.test(type) || !message) {
        return res.status(400).json({ success: false, error: 'Invalid protection event' });
    }

    const screenshotFilename = saveUploadedScreenshot(PROTECTION_SCREENSHOT_DIR, req.file, [
        type,
        session.username || req.body.username || 'user',
        session.hwid || req.body.hwid || 'hwid'
    ]);

    const processId = Number.parseInt(req.body.processId, 10);
    const clientTimestamp = Number.parseInt(req.body.timestamp, 10);
    const event = {
        receivedAt: new Date().toISOString(),
        type,
        message,
        riskScore: riskScoreForEvent(type),
        hwid: session.hwid || cleanString(req.body.hwid, 128),
        username: session.username || cleanString(req.body.username, 128),
        pcName: session.pcName || cleanString(req.body.pcName, 128),
        buildId: session.buildId || cleanString(req.body.buildId, 128),
        appVersion: session.appVersion || cleanString(req.body.appVersion, 32),
        screenshotFilename,
        screenshotUrl: screenshotFilename ? `/dashboard/protection-screenshot/${encodeURIComponent(screenshotFilename)}` : '',
        screenshotStatus: cleanString(req.body.screenshotStatus, 64) || (screenshotFilename ? 'saved' : 'missing'),
        uploadMime: req.file ? cleanString(req.file.mimetype, 80) : '',
        uploadBytes: req.file?.buffer?.length || 0,
        sessionTokenPrefix: cleanString(req.body.token, 128).slice(0, 12),
        sessionVerified: Boolean(validated),
        processId: Number.isSafeInteger(processId) ? processId : null,
        clientTimestamp: Number.isSafeInteger(clientTimestamp) ? clientTimestamp : null,
        sourceIp: req.ip
    };

    try {
        fs.appendFileSync(PROTECTION_LOG_FILE, `${JSON.stringify(event)}\n`, { encoding: 'utf8', mode: 0o600 });
        logToFile(`PROTECTION - Type: ${event.type} | User: ${event.username || 'Unknown'} | Message: ${event.message}`);
        broadcastToClients('protection_event', event);

        const webhook = {
            title: `Protection: ${event.type}`,
            description: event.message,
            color: 0xFF0000,
            fields: [
                { name: 'User', value: event.username || 'Unknown', inline: true },
                { name: 'PC', value: event.pcName || 'Unknown', inline: true },
                { name: 'HWID', value: event.hwid || 'Unknown', inline: true },
                { name: 'PID', value: String(event.processId ?? 'Unknown'), inline: true },
                { name: 'Build', value: event.buildId || 'Unknown', inline: true },
                { name: 'Risk', value: String(event.riskScore), inline: true },
                { name: 'Screenshot', value: event.screenshotFilename ? `Captured (${event.uploadBytes} bytes)` : (event.screenshotStatus || 'Not captured'), inline: true },
                { name: 'Session', value: event.sessionVerified ? 'Verified' : 'Unverified alert accepted', inline: true }
            ],
            timestamp: event.receivedAt
        };
        const attachment = event.screenshotFilename && req.file?.buffer?.length ? {
            buffer: req.file.buffer,
            filename: event.screenshotFilename,
            contentType: req.file.mimetype || 'image/jpeg'
        } : null;
        if (attachment) webhook.image = { url: `attachment://${attachment.filename}` };
        sendDiscordWebhook(webhook, attachment).catch(error => console.error('Protection webhook error:', error.message));
        return res.status(202).json({ success: true });
    } catch (error) {
        console.error('Protection event persistence error:', error.message);
        return res.status(500).json({ success: false, error: 'Unable to persist event' });
    }
});

app.post('/api/crash/report', (req, res) => {
    const clean = (value, max) => typeof value === 'string' ? value.slice(0, max) : '';
    const report = {
        receivedAt: new Date().toISOString(),
        type: 'CRASH_REPORT',
        riskScore: riskScoreForEvent('CRASH_REPORT'),
        exceptionCode: clean(req.body.exceptionCode, 32),
        exceptionAddress: clean(req.body.exceptionAddress, 64),
        instructionPointer: clean(req.body.instructionPointer, 64),
        stackPointer: clean(req.body.stackPointer, 64),
        module: clean(req.body.module, 260),
        crashOffset: clean(req.body.crashOffset, 64),
        hwid: clean(req.body.hwid, 128),
        username: clean(req.body.username, 128),
        pcName: clean(req.body.pcName, 128),
        buildId: clean(req.body.buildId, 128),
        appVersion: clean(req.body.appVersion, 32),
        sourceIp: req.ip
    };
    appendJsonLine(CRASH_REPORT_FILE, report);
    broadcastToClients('crash_report', report);
    res.status(202).json({ success: true });
});

app.post('/api/canary/trigger', upload.single('screenshot'), (req, res) => {
    req.body.token = cleanString(req.body.token || req.body.sessionToken, 128);
    req.body.signature = cleanString(req.body.signature || req.body.sessionSignature, 128);
    req.body.hwid = cleanString(req.body.hwid, 128);
    req.body.buildId = cleanString(req.body.buildId, 128);
    const validated = validatePlainClientSession(req, res);
    if (!validated) return;
    const { session } = validated;
    const screenshotFilename = saveUploadedScreenshot(PROTECTION_SCREENSHOT_DIR, req.file, [
        'CANARY_TRIGGERED',
        session.username || req.body.username || 'user',
        session.hwid || req.body.hwid || 'hwid'
    ]);
    const event = {
        receivedAt: new Date().toISOString(),
        type: 'CANARY_TRIGGERED',
        riskScore: riskScoreForEvent('CANARY_TRIGGERED'),
        baitId: cleanString(req.body.baitId, 64),
        reason: cleanString(req.body.reason, 512),
        hwid: session.hwid || cleanString(req.body.hwid, 128),
        username: session.username || cleanString(req.body.username, 128),
        pcName: session.pcName || cleanString(req.body.pcName, 128),
        buildId: session.buildId || cleanString(req.body.buildId, 128),
        appVersion: session.appVersion || cleanString(req.body.appVersion, 32),
        screenshotFilename,
        screenshotUrl: screenshotFilename ? `/dashboard/protection-screenshot/${encodeURIComponent(screenshotFilename)}` : '',
        screenshotStatus: cleanString(req.body.screenshotStatus, 64) || (screenshotFilename ? 'saved' : 'missing'),
        uploadMime: req.file ? cleanString(req.file.mimetype, 80) : '',
        uploadBytes: req.file?.buffer?.length || 0,
        sourceIp: req.ip
    };
    appendJsonLine(CANARY_REPORT_FILE, event);
    broadcastToClients('canary_event', event);
    const webhook = {
        title: `Canary Triggered: ${event.baitId || 'unknown'}`,
        description: event.reason || 'Bait value was touched',
        color: 0xFF9900,
        fields: [
            { name: 'HWID', value: event.hwid || 'Unknown', inline: true },
            { name: 'Build', value: event.buildId || 'Unknown', inline: true },
            { name: 'Risk', value: String(event.riskScore), inline: true },
            { name: 'Screenshot', value: event.screenshotFilename ? `Captured (${event.uploadBytes} bytes)` : (event.screenshotStatus || 'Not captured'), inline: true }
        ],
        timestamp: event.receivedAt
    };
    const attachment = event.screenshotFilename && req.file?.buffer?.length ? {
        buffer: req.file.buffer,
        filename: event.screenshotFilename,
        contentType: req.file.mimetype || 'image/jpeg'
    } : null;
    if (attachment) webhook.image = { url: `attachment://${attachment.filename}` };
    sendDiscordWebhook(webhook, attachment).catch(error => console.error('Canary webhook error:', error.message));
    res.status(202).json({ success: true });
});

app.post('/api/protection/action', (req, res) => {
    const clean = (value, max) => typeof value === 'string' ? value.slice(0, max) : '';
    const action = clean(req.body.action, 32).toLowerCase();
    if (!['flag', 'ban', 'ignore'].includes(action)) {
        return res.status(400).json({ success: false, error: 'Invalid action' });
    }
    const record = {
        receivedAt: new Date().toISOString(),
        action,
        type: clean(req.body.type, 64),
        hwid: clean(req.body.hwid, 128),
        buildId: clean(req.body.buildId, 128),
        note: clean(req.body.note, 512),
        sourceIp: req.ip
    };
    appendJsonLine(PROTECTION_ACTIONS_FILE, record);
    if (action === 'ban' && record.hwid) {
        const banned = loadBanned();
        if (!banned.sids.includes(record.hwid)) banned.sids.push(record.hwid);
        saveBanned(banned);
    }
    broadcastToClients('protection_action', record);
    res.json({ success: true });
});

// ENDPOINT: Cleanup session started
app.post('/api/cleanup/start', async (req, res) => {
    const { session_id, action, process_id, timestamp } = req.body;

    console.log(`> Cleanup started - Session: ${session_id} - PID: ${process_id}`);

    await sendCleanupWebhook({
        title: '🧹 Cleanup Started',
        color: 0x3498DB, // Blue
        fields: [
            { name: 'Session ID', value: session_id || 'Unknown', inline: true },
            { name: 'Process ID', value: String(process_id) || 'Unknown', inline: true },
            { name: 'Action', value: action || 'cleanup_start', inline: true },
            { name: 'Timestamp', value: timestamp ? new Date(timestamp * 1000).toLocaleString() : new Date().toLocaleString(), inline: false }
        ],
        timestamp: new Date().toISOString()
    });

    res.json({ status: 'ok' });
});

// ENDPOINT: Cleanup status update
app.post('/api/cleanup/status', async (req, res) => {
    const { session_id, phase, status, progress, timestamp } = req.body;

    console.log(`> Cleanup status - Session: ${session_id} - Phase: ${phase} - Progress: ${progress}%`);

    // Color based on progress
    let color = 0x3498DB; // Blue
    if (progress >= 75) color = 0x2ECC71; // Green
    else if (progress >= 50) color = 0xF1C40F; // Yellow
    else if (progress >= 25) color = 0xE67E22; // Orange

    await sendCleanupWebhook({
        title: `📊 Cleanup Progress: ${progress}%`,
        color: color,
        fields: [
            { name: 'Session ID', value: session_id || 'Unknown', inline: true },
            { name: 'Phase', value: phase || 'Unknown', inline: true },
            { name: 'Progress', value: `${progress}%`, inline: true },
            { name: 'Status', value: status || 'Working...', inline: false },
            { name: 'Timestamp', value: timestamp ? new Date(timestamp * 1000).toLocaleString() : new Date().toLocaleString(), inline: false }
        ],
        timestamp: new Date().toISOString()
    });

    res.json({ status: 'ok' });
});

// ENDPOINT: Cleanup log message
app.post('/api/cleanup/log', async (req, res) => {
    const { session_id, message, timestamp } = req.body;

    console.log(`> Cleanup log - Session: ${session_id} - ${message}`);

    await sendCleanupWebhook({
        title: '📝 Cleanup Log',
        color: 0x9B59B6, // Purple
        fields: [
            { name: 'Session ID', value: session_id || 'Unknown', inline: true },
            { name: 'Message', value: message || 'No message', inline: false },
            { name: 'Timestamp', value: timestamp ? new Date(timestamp * 1000).toLocaleString() : new Date().toLocaleString(), inline: false }
        ],
        timestamp: new Date().toISOString()
    });

    res.json({ status: 'ok' });
});

// ENDPOINT: Cleanup error
app.post('/api/cleanup/error', async (req, res) => {
    const { session_id, type, error, details, timestamp } = req.body;

    console.log(`> Cleanup ERROR - Session: ${session_id} - ${error}`);

    await sendCleanupWebhook({
        title: '❌ Cleanup Error',
        color: 0xE74C3C, // Red
        fields: [
            { name: 'Session ID', value: session_id || 'Unknown', inline: true },
            { name: 'Error Type', value: type || 'error', inline: true },
            { name: 'Error', value: error || 'Unknown error', inline: false },
            { name: 'Details', value: details || 'No details', inline: false },
            { name: 'Timestamp', value: timestamp ? new Date(timestamp * 1000).toLocaleString() : new Date().toLocaleString(), inline: false }
        ],
        timestamp: new Date().toISOString()
    });

    res.json({ status: 'ok' });
});

// ENDPOINT: Cleanup complete
app.post('/api/cleanup/complete', async (req, res) => {
    const { session_id, action, status, timestamp } = req.body;

    console.log(`> Cleanup complete - Session: ${session_id} - Status: ${status}`);

    const isSuccess = status === 'success';

    await sendCleanupWebhook({
        title: isSuccess ? '✅ Cleanup Complete' : '⚠️ Cleanup Finished with Issues',
        color: isSuccess ? 0x2ECC71 : 0xF1C40F, // Green or Yellow
        fields: [
            { name: 'Session ID', value: session_id || 'Unknown', inline: true },
            { name: 'Status', value: status || 'Unknown', inline: true },
            { name: 'Action', value: action || 'cleanup_complete', inline: true },
            { name: 'Timestamp', value: timestamp ? new Date(timestamp * 1000).toLocaleString() : new Date().toLocaleString(), inline: false }
        ],
        timestamp: new Date().toISOString()
    });

    res.json({ status: 'ok' });
});

// ============================================================================
// PIPE ENDPOINTS - Simple HTTP endpoints for C++ clients (no WinHTTP needed)
// Uses raw HTTP POST - compatible with Winsock
// ============================================================================

const PROTECTION_WEBHOOK = process.env.PROTECTION_WEBHOOK_URL || DISCORD_WEBHOOK;
const INFO_WEBHOOK = CLEANUP_WEBHOOK;

// PIPE: Protection Pipe - forwards to protection webhook (supports base64 screenshots)
app.post('/api/pipe/protection', async (req, res) => {
    try {
        const { title, message, color, fields, hwid, username, pcName, ip, timestamp, license, screenshot } = req.body;

        console.log(`> [PROTECTION PIPE] ${title || 'Alert'} - ${username || 'Unknown'}@${pcName || 'Unknown'}`);

        // Build embed
        const embed = {
            title: title || '🛡️ Protection Alert',
            description: message || 'Someone is debugging the scanner!',
            color: color || 0xFF0000,
            fields: fields || [
                { name: 'HWID', value: hwid || 'Unknown', inline: true },
                { name: 'Username', value: username || 'Unknown', inline: true },
                { name: 'PC Name', value: pcName || 'Unknown', inline: true },
                { name: 'Public IP', value: ip || 'Unknown', inline: true },
                { name: 'License', value: license || 'Unknown', inline: true },
                { name: 'Timestamp', value: timestamp ? new Date(parseInt(timestamp) * 1000).toLocaleString() : new Date().toLocaleString(), inline: false }
            ],
            footer: {
                text: 'DIH Protection • ' + new Date().toLocaleString()
            },
            timestamp: new Date().toISOString()
        };

        // If screenshot provided (base64), decode and attach it
        if (screenshot && screenshot.length > 100) {
            const FormData = require('form-data');
            const formData = new FormData();

            // Decode base64 to buffer
            const screenshotBuffer = Buffer.from(screenshot, 'base64');

            // Add screenshot as file attachment
            embed.image = { url: 'attachment://screenshot.jpg' };
            formData.append('file', screenshotBuffer, {
                filename: 'screenshot.jpg',
                contentType: 'image/jpeg'
            });

            // Add embed with @everyone ping
            formData.append('payload_json', JSON.stringify({
                content: '@everyone',
                embeds: [embed]
            }));

            // Send to Discord with screenshot
            await axios.post(PROTECTION_WEBHOOK, formData, {
                headers: formData.getHeaders()
            });

            console.log(`> Screenshot sent (${Math.floor(screenshotBuffer.length / 1024)}KB) - ${username}`);
        } else {
            // No screenshot, just send embed
            await axios.post(PROTECTION_WEBHOOK, {
                content: '@everyone',
                embeds: [embed]
            });
            console.log(`> Alert sent (no screenshot) - ${username}`);
        }

        res.json({ status: 'ok', pipe: 'protection' });
    } catch (error) {
        console.error('Protection pipe error:', error.message);
        res.status(500).json({ status: 'error', message: error.message });
    }
});

// PIPE: Info Pipe - forwards to info webhook
app.post('/api/pipe/info', async (req, res) => {
    try {
        const { title, message, color, fields, phase, progress, hwid, username, pcName, ip, timestamp } = req.body;

        console.log(`> [INFO PIPE] ${title || phase || 'Info'} - ${progress !== undefined ? progress + '%' : ''} - ${username || 'Unknown'}`);

        // Build embed
        const embed = {
            title: title || `📊 ${phase || 'Info'}`,
            description: message || null,
            color: color || 0x3498DB,
            fields: fields || [
                { name: 'Phase', value: phase || 'Unknown', inline: true },
                { name: 'Progress', value: progress !== undefined ? `${progress}%` : 'N/A', inline: true },
                { name: 'Username', value: username || 'Unknown', inline: true },
                { name: 'PC Name', value: pcName || 'Unknown', inline: true },
                { name: 'IP', value: ip || 'Unknown', inline: true },
                { name: 'HWID', value: hwid || 'Unknown', inline: true }
            ],
            timestamp: new Date().toISOString()
        };

        await axios.post(INFO_WEBHOOK, { embeds: [embed] });
        res.json({ status: 'ok', pipe: 'info' });
    } catch (error) {
        console.error('Info pipe error:', error.message);
        res.status(500).json({ status: 'error', message: error.message });
    }
});

// PIPE: Raw data forward (minimal parsing - just forwards JSON body as embed fields)
app.post('/api/pipe/raw', async (req, res) => {
    try {
        const { pipe, data } = req.body; // pipe = "info" or "protection"
        const webhook = pipe === 'protection' ? PROTECTION_WEBHOOK : INFO_WEBHOOK;

        console.log(`> [RAW PIPE] ${pipe} - ${JSON.stringify(data).substring(0, 50)}...`);

        // Convert data object to embed fields
        const fields = Object.entries(data || {}).map(([key, value]) => ({
            name: key,
            value: String(value).substring(0, 1024),
            inline: true
        }));

        const embed = {
            title: pipe === 'protection' ? '🛡️ Protection Data' : '📊 Info Data',
            color: pipe === 'protection' ? 0xFF0000 : 0x3498DB,
            fields: fields,
            timestamp: new Date().toISOString()
        };

        await axios.post(webhook, { embeds: [embed] });
        res.json({ status: 'ok' });
    } catch (error) {
        console.error('Raw pipe error:', error.message);
        res.status(500).json({ status: 'error', message: error.message });
    }
});

// SIMPLE TEST ENDPOINT - for testing raw Winsock connections
app.get('/api/test', (req, res) => {
    console.log('> TEST endpoint hit from:', req.ip);
    res.json({ status: 'ok', message: 'Server is reachable', timestamp: Date.now() });
});

app.post('/api/test', (req, res) => {
    console.log('> TEST POST endpoint hit from:', req.ip);
    console.log('> Body:', req.body);
    res.json({ status: 'ok', message: 'POST received', data: req.body, timestamp: Date.now() });
});

// GET CLIENT IP - DLL uses this to get real IP
app.post('/api/get-ip', (req, res) => {
    const clientIP = req.ip || req.connection.remoteAddress || 'UNKNOWN';
    console.log('> IP request from:', clientIP);
    res.json({ status: 'ok', ip: clientIP, timestamp: Date.now() });
});

// ============================================================================
// SECURE API ENDPOINTS - Protected with HMAC, nonces, timestamps
// ============================================================================

// SECURE: Initialize session (first call from client)
app.post('/api/secure/init', security.secureEndpoint(false), async (req, res) => {
    const { hwid, license, username, computerName, ip } = req.securePayload;

    const licenseCheck = await verifyPanelLicense(license, { hwid });
    if (!licenseCheck.success) return security.sendSignedResponse(res, { success:false, allowed:false, reason:licenseCheck.message || 'Invalid license', code:'INVALID_LICENSE' }, req.clientSecret);

    console.log(`> [SECURE] Session init - ${username}@${computerName} - HWID: ${hwid.substring(0, 16)}...`);

    // Check ban status
    const banned = loadBanned();
    const isBanned = banned.sids.includes(hwid) || banned.ips.includes(ip);

    if (isBanned) {
        console.log(`> [SECURE] BLOCKED - Banned user: ${username}`);
        return security.sendSignedResponse(res, {
            success: false,
            allowed: false,
            reason: 'User is banned',
            code: 'BANNED'
        }, req.clientSecret);
    }

    // Create session
    const session = security.createSession(hwid, license, { username, computerName, ip });

    // Log successful init
    logToFile(`SECURE_INIT - User: ${username} | PC: ${computerName} | HWID: ${hwid.substring(0, 16)}...`);

    security.sendSignedResponse(res, {
        success: true,
        allowed: true,
        sessionToken: session.token,
        sessionExpiry: session.expiry
    }, req.clientSecret);
});

// SECURE: Check ban status (requires valid session)
app.post('/api/secure/check', security.secureEndpoint(true), async (req, res) => {
    const { hwid, ip, gpuHwid, cpuHwid, diskHwid, username, computerName } = req.securePayload;

    console.log(`> [SECURE] Ban check - ${username}@${computerName}`);

    const banned = loadBanned();

    const isBanned =
        banned.sids.includes(hwid) ||
        banned.ips.includes(ip) ||
        banned.gpuHwids.includes(gpuHwid) ||
        banned.cpuHwids.includes(cpuHwid) ||
        banned.diskHwids.includes(diskHwid);

    if (isBanned) {
        console.log(`> [SECURE] BLOCKED - Banned: ${username}`);
        logToFile(`SECURE_BAN_BLOCKED - User: ${username} | IP: ${ip}`);

        await sendDiscordWebhook({
            title: '🔒 Secure API - Banned User Blocked',
            color: 0xFF0000,
            fields: [
                { name: 'Username', value: username || 'Unknown', inline: true },
                { name: 'Computer', value: computerName || 'Unknown', inline: true },
                { name: 'IP Address', value: ip || 'Unknown', inline: true }
            ],
            timestamp: new Date().toISOString()
        });

        return security.sendSignedResponse(res, {
            success: true,
            allowed: false,
            reason: 'User is banned'
        }, req.clientSecret);
    }

    security.sendSignedResponse(res, {
        success: true,
        allowed: true
    }, req.clientSecret);
});

// SECURE: Heartbeat (keep session alive, verify client integrity)
app.post('/api/secure/heartbeat', security.secureEndpoint(true), (req, res) => {
    const { hwid, integrityHash } = req.securePayload;

    // Extend session
    const session = req.session;
    const now = Math.floor(Date.now() / 1000);
    session.expiry = now + security.CONFIG.SESSION_DURATION;
    session.lastHeartbeat = now;

    security.sendSignedResponse(res, {
        success: true,
        sessionExpiry: session.expiry,
        serverTime: now
    }, req.clientSecret);
});

// SECURE: Integrity verification
app.post('/api/secure/integrity', security.secureEndpoint(true), async (req, res) => {
    const { fileName, fileHash, hwid, username, pcName, ip, license } = req.securePayload;

    if (!fileName || !fileHash) {
        return security.sendSignedResponse(res, {
            success: false,
            valid: false,
            error: 'Missing fileName or fileHash'
        }, req.clientSecret);
    }

    const hashDB = loadHashes();

    // Setup mode
    if (hashDB.setupMode === true) {
        console.log(`> [SECURE] Setup mode - Registering hash for ${fileName}`);

        if (!hashDB.files) hashDB.files = {};
        hashDB.files[fileName] = {
            hash: fileHash,
            lastUpdated: new Date().toISOString(),
            notes: `Secure registration from ${username}@${pcName}`
        };
        saveHashes(hashDB);

        return security.sendSignedResponse(res, {
            success: true,
            valid: true,
            setupMode: true
        }, req.clientSecret);
    }

    // Production mode - verify
    const expectedFile = hashDB.files[fileName];

    if (!expectedFile || !expectedFile.hash) {
        return security.sendSignedResponse(res, {
            success: false,
            valid: false,
            error: 'File not registered'
        }, req.clientSecret);
    }

    const isValid = fileHash.toLowerCase() === expectedFile.hash.toLowerCase();

    if (!isValid) {
        console.log(`> [SECURE] INTEGRITY VIOLATION - ${fileName} - ${username}@${pcName}`);
        logToFile(`SECURE_INTEGRITY_FAIL - File: ${fileName} | User: ${username} | IP: ${ip}`);

        await sendDiscordWebhook({
            title: '🔒🚨 Secure API - Integrity Violation',
            color: 0xFF0000,
            fields: [
                { name: 'File', value: fileName, inline: true },
                { name: 'Username', value: username || 'Unknown', inline: true },
                { name: 'HWID', value: hwid ? hwid.substring(0, 16) + '...' : 'Unknown', inline: true },
                { name: 'Expected', value: `\`${expectedFile.hash.substring(0, 24)}...\``, inline: false },
                { name: 'Received', value: `\`${fileHash.substring(0, 24)}...\``, inline: false }
            ],
            timestamp: new Date().toISOString()
        });

        return security.sendSignedResponse(res, {
            success: true,
            valid: false,
            tampered: true
        }, req.clientSecret);
    }

    security.sendSignedResponse(res, {
        success: true,
        valid: true
    }, req.clientSecret);
});

// SECURE: Log event (protection alerts, etc.)
app.post('/api/secure/log', security.secureEndpoint(true), async (req, res) => {
    const { type, message, details, hwid, username, pcName, ip } = req.securePayload;

    console.log(`> [SECURE] Log: ${type} - ${message}`);
    logToFile(`SECURE_LOG - Type: ${type} | User: ${username} | Message: ${message}`);

    let color = 0x0099FF;
    if (type.includes('DEBUG') || type.includes('DETECTION')) color = 0xFFFF00;
    if (type.includes('BAN') || type.includes('VIOLATION')) color = 0xFF0000;

    await sendDiscordWebhook({
        title: `🔒 ${type}`,
        description: message,
        color: color,
        fields: [
            { name: 'Username', value: username || 'Unknown', inline: true },
            { name: 'PC Name', value: pcName || 'Unknown', inline: true },
            { name: 'IP', value: ip || 'Unknown', inline: true },
            ...(details ? Object.entries(details).map(([key, value]) => ({
                name: key,
                value: String(value),
                inline: true
            })) : [])
        ],
        timestamp: new Date().toISOString()
    });

    security.sendSignedResponse(res, { success: true }, req.clientSecret);
});

// SECURE: Get server time (for clock sync)
app.get('/api/secure/time', (req, res) => {
    res.json({
        serverTime: Math.floor(Date.now() / 1000),
        timestamp: Date.now()
    });
});

// Security stats endpoint (for monitoring)
app.get('/api/secure/stats', (req, res) => {
    res.json({
        activeSessions: security.sessions.size,
        usedNonces: security.usedNonces.size,
        config: {
            timestampTolerance: security.CONFIG.TIMESTAMP_TOLERANCE,
            sessionDuration: security.CONFIG.SESSION_DURATION
        }
    });
});

// Protection status - detailed view for debugging
app.get('/api/protection/status', (req, res) => {
    const now = Math.floor(Date.now() / 1000);

    // Get active sessions with last activity
    const activeSessions = [];
    for (const [token, session] of security.sessions.entries()) {
        if (now < session.expiry) {
            activeSessions.push({
                hwid: session.hwid ? session.hwid.substring(0, 8) + '...' : 'Unknown',
                username: session.username || 'Unknown',
                computerName: session.computerName || 'Unknown',
                created: new Date(session.created * 1000).toISOString(),
                expiry: new Date(session.expiry * 1000).toISOString(),
                lastHeartbeat: session.lastHeartbeat ? new Date(session.lastHeartbeat * 1000).toISOString() : 'Never',
                timeRemaining: Math.max(0, session.expiry - now) + 's'
            });
        }
    }

    res.json({
        status: 'online',
        serverTime: new Date().toISOString(),
        protection: {
            activeSessions: activeSessions.length,
            usedNonces: security.usedNonces.size,
            sessions: activeSessions,
            recentEvents: readJsonLines(PROTECTION_LOG_FILE, 50),
            recentCrashes: readJsonLines(CRASH_REPORT_FILE, 20),
            recentCanaries: readJsonLines(CANARY_REPORT_FILE, 20),
            recentActions: readJsonLines(PROTECTION_ACTIONS_FILE, 20)
        },
        control: loadJsonFile(CONTROL_CONFIG_FILE, DEFAULT_CONTROL_CONFIG),
        config: {
            timestampTolerance: security.CONFIG.TIMESTAMP_TOLERANCE + 's',
            sessionDuration: security.CONFIG.SESSION_DURATION + 's',
            nonceExpiry: security.CONFIG.NONCE_EXPIRY + 's'
        }
    });
});

// ============================================================================
// SCREENSHOT HEARTBEAT SYSTEM - Stores screenshots, detects freezes
// ============================================================================

// Store last screenshot per HWID
const clientScreenshots = new Map(); // hwid -> { screenshot, timestamp, hwid, username, pcName, license, ip }

// ENDPOINT: Heartbeat with screenshot (every 3 seconds from client)
app.post('/api/heartbeat/screenshot', upload.single('screenshot'), async (req, res) => {
    try {
        const validated = validatePlainClientSession(req, res);
        if (!validated) return;
        const { session } = validated;
        const { hwid, username, pcName, license, ip, timestamp } = req.body;
        const screenshot = req.file;

        if (!hwid) {
            return res.status(400).json({ success: false, error: 'Missing hwid' });
        }

        const now = Date.now();

        // Store the latest data for this client
        clientScreenshots.set(hwid, {
            screenshot: screenshot ? screenshot.buffer : null,
            timestamp: now,
            hwid,
            username: session.username || username || 'Unknown',
            pcName: session.pcName || pcName || 'Unknown',
            license: session.licenseKey || license || 'Unknown',
            ip: ip || req.ip || 'Unknown',
            alerted: false // Track if we already sent timeout alert
        });

        console.log(`> [SCREENSHOT HB] ${username}@${pcName} - ${screenshot ? Math.round(screenshot.buffer.length/1024) + 'KB' : 'no screenshot'}`);

        res.json({ success: true, serverTime: now });
    } catch (error) {
        console.error('Screenshot heartbeat error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ENDPOINT: Graceful disconnect (client closing normally - don't trigger alert)
app.post('/api/heartbeat/disconnect', (req, res) => {
    const { hwid, reason } = req.body;

    if (hwid && clientScreenshots.has(hwid)) {
        const data = clientScreenshots.get(hwid);
        console.log(`> [DISCONNECT] ${data.username}@${data.pcName} - Reason: ${reason || 'normal_close'}`);
        clientScreenshots.delete(hwid);
    }

    res.json({ success: true });
});

// ENDPOINT: Get client status (for debugging)
app.get('/api/heartbeat/status', (req, res) => {
    const now = Date.now();
    const clients = [];

    for (const [hwid, data] of clientScreenshots.entries()) {
        const age = Math.round((now - data.timestamp) / 1000);
        clients.push({
            hwid: hwid.substring(0, 16) + '...',
            username: data.username,
            pcName: data.pcName,
            lastSeen: age + 's ago',
            hasScreenshot: !!data.screenshot,
            status: age > 4 ? '⚠️ TIMEOUT' : '✅ OK'
        });
    }

    res.json({
        totalClients: clientScreenshots.size,
        clients
    });
});

// Background job: Check for frozen clients every second
setInterval(async () => {
    const now = Date.now();
    const TIMEOUT_MS = 4000; // 4 seconds

    for (const [hwid, data] of clientScreenshots.entries()) {
        const age = now - data.timestamp;

        // If no heartbeat for 5+ seconds and we haven't alerted yet
        if (age > TIMEOUT_MS && !data.alerted) {
            console.log(`> [FREEZE DETECTED] ${data.username}@${data.pcName} - No heartbeat for ${Math.round(age/1000)}s`);

            // Mark as alerted so we don't spam
            data.alerted = true;

            // Send Discord webhook with screenshot
            try {
                const formData = new FormData();

                const embed = {
                    title: '⚠️ WARNING: Connection Lost (Possible Debugging)',
                    description: 'Client stopped sending heartbeats (4+ seconds)',
                    color: 0xFFA500, // Orange - warning, not ban
                    fields: [
                        { name: 'Username', value: data.username, inline: true },
                        { name: 'PC Name', value: data.pcName, inline: true },
                        { name: 'HWID', value: data.hwid ? data.hwid.substring(0, 32) + '...' : 'Unknown', inline: false },
                        { name: 'License', value: data.license, inline: true },
                        { name: 'IP Address', value: data.ip, inline: true },
                        { name: 'Last Seen', value: Math.round(age/1000) + ' seconds ago', inline: true },
                        { name: 'Status', value: '⚠️ WARNING ONLY - Not banned', inline: false }
                    ],
                    footer: { text: 'Freeze Detection System • Review manually' },
                    timestamp: new Date().toISOString()
                };

                // If we have a screenshot, attach it
                if (data.screenshot && data.screenshot.length > 0) {
                    embed.image = { url: 'attachment://last_screenshot.jpg' };
                    formData.append('file', data.screenshot, {
                        filename: 'last_screenshot.jpg',
                        contentType: 'image/jpeg'
                    });
                }

                formData.append('payload_json', JSON.stringify({
                    content: '@everyone ⚠️ WARNING: Connection lost (possible debugging) - review last screenshot',
                    embeds: [embed]
                }));

                await axios.post(DISCORD_WEBHOOK, formData, {
                    headers: formData.getHeaders()
                });

                console.log(`> [FREEZE ALERT] Sent to Discord - ${data.username}`);
            } catch (error) {
                console.error('Freeze alert error:', error.message);
            }
        }

        // Clean up old entries (older than 5 minutes)
        if (age > 300000) {
            clientScreenshots.delete(hwid);
            console.log(`> [CLEANUP] Removed stale client: ${data.username}`);
        }
    }
}, 1000); // Check every second

let server;
if (IS_PRODUCTION) {
    const keyPath=process.env.TLS_KEY_PATH, certPath=process.env.TLS_CERT_PATH;
    if(!keyPath||!certPath) throw new Error('Production requires TLS_KEY_PATH and TLS_CERT_PATH');
    server=https.createServer({key:fs.readFileSync(keyPath),cert:fs.readFileSync(certPath)},app);
} else {
    server=require('http').createServer(app);
}

server.listen(PORT, IS_PRODUCTION ? '0.0.0.0' : '127.0.0.1', () => {
    console.log('> bypass-backend@1.0.0 start');
    console.log('> node server.js');
    console.log('');
    console.log(`Mode: ${IS_PRODUCTION?'production HTTPS':'local HTTP'}`);
    console.log('Local: http://127.0.0.1:' + PORT);
    console.log(`Discord webhook: ${DISCORD_WEBHOOK?'configured':'disabled'}`);
    console.log('');
    console.log('Test endpoints:');
    console.log('  GET  /api/test            -> Connection test');
    console.log('  POST /api/test            -> POST test');
    console.log('');
    console.log('Cleanup endpoints:');
    console.log('  POST /api/cleanup/start   -> Cleanup webhook');
    console.log('  POST /api/cleanup/status  -> Cleanup webhook');
    console.log('  POST /api/cleanup/log     -> Cleanup webhook');
    console.log('  POST /api/cleanup/error   -> Cleanup webhook');
    console.log('  POST /api/cleanup/complete-> Cleanup webhook');
    console.log('');
    console.log('Pipe endpoints:');
    console.log('  POST /api/pipe/protection -> Protection webhook');
    console.log('  POST /api/pipe/info       -> Info webhook');
    console.log('  POST /api/pipe/raw        -> Dynamic routing');
    console.log('');
    console.log('Secure endpoints (HMAC + nonce + timestamp):');
    console.log('  POST /api/secure/init      -> Initialize session');
    console.log('  POST /api/secure/check     -> Ban check (requires session)');
    console.log('  POST /api/secure/heartbeat -> Keep session alive');
    console.log('  POST /api/secure/integrity -> File integrity check');
    console.log('  POST /api/secure/log       -> Secure event logging');
    console.log('  GET  /api/secure/time      -> Server time sync');
    console.log('  GET  /api/secure/stats     -> Security stats');
    console.log('  GET  /api/protection/status-> Protection dashboard');
    console.log('');
    console.log('Waiting for connections...');
});
