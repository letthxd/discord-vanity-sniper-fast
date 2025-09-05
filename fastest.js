"use strict";
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";
const tls = require("tls");
const WebSocket = require("ws");
const fs = require("fs");
const path = require("path");
const http2 = require("http2");
const dns = require("dns");
let vanity, websocket, mfaToken;
const token = "MTM2MTcwNzA5NDQ3MDAzNzY4NA.G1XPlX.";
const swid = "1381328853443809280";
const guilds = {};
const vanityRequestCache = new Map();
const CONNECTION_POOL_SIZE = 3;
const tlsConnections = [];
const http2Pool = [];
const claimBuffer = [];
function loadMfaToken() {
    try {
        const data = JSON.parse(fs.readFileSync(path.join(__dirname, 'mfa_token.json'), 'utf8'));
        if (data.token) {
            mfaToken = data.token;
            console.log("Loaded MFA token from file.");
            return true;
        }
    } catch (err) {
        console.log("Error loading MFA token:", err.message);
    }
    return false;
}
setInterval(loadMfaToken, 10000);
function getVanityPatchRequestBuffer(vanityCode) {
    if (vanityRequestCache.has(vanityCode)) return vanityRequestCache.get(vanityCode);
    const payload = JSON.stringify({ code: vanityCode });
    const payloadLength = Buffer.byteLength(payload);
    const buffer = Buffer.from(
        `PATCH /api/v8/guilds/${swid}/vanity-url HTTP/1.1\r\n` +
        `Host: canary.discord.com\r\n` +
        `Authorization: ${token}\r\n` +
        `X-Discord-MFA-Authorization: ${mfaToken}\r\n` +
        `User-Agent: Mozilla/5.0\r\n` +
        `X-Super-Properties: eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==\r\n` +
        `Content-Type: application/json\r\n` +
        `Connection: keep-alive\r\n` +
        `Content-Length: ${payloadLength}\r\n\r\n` +
        payload
    );
    vanityRequestCache.set(vanityCode, buffer);
    return buffer;
}
function createTlsConnection() {
    const options = {
        host: "canary.discord.com",
        port: 443,
        minVersion: "TLSv1.3",
        maxVersion: "TLSv1.3",
        rejectUnauthorized: false,
        keepAlive: true,
        servername: "canary.discord.com",
        ALPNProtocols: ['h2', 'http/1.1'],
        ciphers: 'TLS_AES_128_GCM_SHA256',
        ecdhCurve: 'X25519',
        honorCipherOrder: true
    };
    const conn = tls.connect(options);
    conn.setNoDelay(true);
    conn.on("secureConnect", () => {
        console.log("TLS connection established with ALPN:", conn.alpnProtocol);
        tlsConnections.push(conn);
    });
    conn.on("error", (err) => { console.log("TLS connection error:", err); reconnect(conn); });
    conn.on("end", () => { console.log("TLS connection ended"); reconnect(conn); });
    return conn;
}
function reconnect(conn) {
    const idx = tlsConnections.indexOf(conn);
    if (idx !== -1) tlsConnections.splice(idx, 1);
    createTlsConnection();
}
function initConnectionPool() {
    for (let i = 0; i < CONNECTION_POOL_SIZE; i++) createTlsConnection();
}
function createHttp2Session() {
    const session = http2.connect('https://canary.discord.com', { settings: { enablePush: false } });
    session.on('error', () => session.destroy());
    session.on('close', () => session.destroy());
    http2Pool.push({ session, inUse: false });
    return session;
}
function getHttp2Session() {
    let sessObj = http2Pool.find(s => !s.inUse && !s.session.destroyed);
    if (!sessObj) {
        const session = createHttp2Session();
        sessObj = { session, inUse: false };
        http2Pool.push(sessObj);
    }
    sessObj.inUse = true;
    return sessObj;
}
async function requestHTTP2(path, body = null) {
    const sessObj = getHttp2Session();
    const headers = {
        ':method': 'PATCH',
        ':path': path,
        'authorization': token,
        'x-discord-mfa-authorization': mfaToken,
        'content-type': 'application/json',
        'user-agent': 'Mozilla/5.0',
        'x-super-properties': 'eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ=='
    };
    return new Promise((resolve, reject) => {
        const stream = sessObj.session.request(headers);
        const chunks = [];
        stream.on('data', chunk => chunks.push(chunk));
        stream.on('end', () => { sessObj.inUse=false; resolve(Buffer.concat(chunks).toString()); });
        stream.on('error', err => { sessObj.inUse=false; reject(err); });
        if(body) stream.end(body); else stream.end();
    });
}
async function processClaimBuffer() {
    while(claimBuffer.length){
        const code = claimBuffer.shift();
        const buffer = getVanityPatchRequestBuffer(code);
        const tlsPromises = tlsConnections
            .filter(c => c.writable && c.authorized)
            .map(c => new Promise(res => c.write(buffer, res)));
        const http2Promises = Array.from({length: 4}, () => requestHTTP2(`/api/v8/guilds/${swid}/vanity-url`, JSON.stringify({ code })));
        await Promise.all([...tlsPromises, ...http2Promises]);
        console.log(`${code}`);
    }
}
function createWebSocket(url, hostHeader='gateway-us-east1-b.discord.gg') {
    const ws = new WebSocket(url, { perMessageDeflate: false, headers: { Host: hostHeader } });
    ws.on('open', () => { if(ws._socket){ ws._socket.setNoDelay(true); ws._socket.setKeepAlive(true,0); } 
        ws.send(JSON.stringify({ op: 2, d: { token, intents: 513, properties: { $os: 'Windows', $browser: 'Chrome', $device: 'Desktop' } } }));
    });
    ws.on('message', async data => {
        const payload = JSON.parse(data);
        if(payload.s) lastSequence = payload.s;

        if(payload.op === 10){
            setInterval(() => ws.send(JSON.stringify({ op: 1, d: lastSequence })), payload.d.heartbeat_interval || 10000);
        }
        if(payload.op === 0 && (payload.t==='GUILD_UPDATE' || payload.t==='GUILD_DELETE')){
            const code = guilds[payload.d.guild_id];
            if(code){
                console.log(`Detected vanity update: ${code} for guild ${payload.d.guild_id}`);
                claimBuffer.push(code);
                processClaimBuffer();
            }
        }
        if(payload.op===0 && payload.t==='READY'){
            payload.d.guilds.forEach(g => { if(g.vanity_url_code) guilds[g.id]=g.vanity_url_code; });
            console.log("READY event processed.");
        }
    });
    ws.on('close', () => setTimeout(()=>createWebSocket(url, hostHeader), 2000));
    ws.on('error', () => ws.close());
}
function connectDNSWS() {
    for(let i=0;i<2;i++){
        dns.lookup('gateway-us-east1-b.discord.gg', (err,address)=>{
            createWebSocket(err ? 'wss://gateway.discord.gg' : `wss://${address}/?encoding=json&v=8`, 'gateway-us-east1-b.discord.gg');
        });
    }
}
function connectDefaultWS(){ for(let i=0;i<6;i++) createWebSocket('wss://gateway.discord.gg'); }
function initialize() {
    loadMfaToken();
    initConnectionPool();
    Array.from({length: 5}).forEach(createHttp2Session);
    connectDefaultWS();
    connectDNSWS();
    setInterval(() => {
        tlsConnections.forEach(c => c.writable && c.write("GET / HTTP/1.1\r\nHost: canary.discord.com\r\nConnection: keep-alive\r\n\r\n"));
    }, 7500);
    console.log("Initialization complete.");
}
initialize();
