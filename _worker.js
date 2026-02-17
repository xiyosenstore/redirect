import { connect } from "cloudflare:sockets";

// --- CONFIGURATION ---
const PRX_BANK_URL = 'https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt';
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
  host: "udp-relay.hobihaus.space",
  port: 7300,
};

let prxIP = "";
let cachedPrxList = [];
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

async function getPrxList() {
  const prxBank = await fetch(PRX_BANK_URL);
  if (prxBank.status == 200) {
    const text = (await prxBank.text()) || "";
    const prxString = text.split("\n").filter(Boolean);
    cachedPrxList = prxString.map((entry) => {
      const [ip, port, country, org] = entry.split(",");
      return {
        prxIP: ip || "Unknown",
        prxPort: port || "Unknown",
        country: country?.toUpperCase() || "Unknown",
        org: org || "Unknown Org",
      };
    });
  }
  return cachedPrxList;
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      if (upgradeHeader === "websocket") {
        const path = url.pathname.replace("/", "");
        
        // Handle path negara (contoh: /SG atau /ID)
        if (path.length === 2) {
          const list = await getPrxList();
          const filtered = list.filter(p => p.country === path.toUpperCase());
          if (filtered.length > 0) {
            const selected = filtered[Math.floor(Math.random() * filtered.length)];
            prxIP = `${selected.prxIP}:${selected.prxPort}`;
          }
        } 
        // Handle manual IP (contoh: /1.2.3.4:443)
        else if (path.match(/^(.+[:=-]\d+)$/)) {
          prxIP = path.replace(/[=:-]/, ":");
        }

        if (!prxIP) return new Response("Proxy Not Found", { status: 404 });
        return await websocketHandler(request);
      }

      return new Response("Worker is running. Use /CC (e.g. /SG) in your VPN app.");
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

// --- CORE HANDLERS ---
async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const log = (info) => console.log(`[Proxy: ${prxIP}] ${info}`);
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (isDNS) return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log, RELAY_SERVER_UDP);
      
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const protocol = await protocolSniffer(chunk);
      let protocolHeader;

      if (protocol === "Trojan") protocolHeader = parseTrojanHeader(chunk);
      else if (protocol === "VLESS") protocolHeader = parseVlessHeader(chunk);
      else protocolHeader = parseSSHeader(chunk);

      if (protocolHeader.isUDP && protocolHeader.portRemote === 53) {
        isDNS = true;
        return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, protocolHeader.version, log, RELAY_SERVER_UDP);
      }

      handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version, log);
    }
  })).catch(e => log("Pipe error: " + e));

  return new Response(null, { status: 101, webSocket: client });
}

// Tambahkan fungsi helper dari _worker (1).js (handleTCPOutBound, handleUDPOutbound, parseVlessHeader, dll.) di sini...
// (Gunakan fungsi dari file _worker (1).js yang kamu kirim tadi untuk bagian parser ini)

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const parts = prxIP.split(/[:=-]/);
    const tcpSocket = await connectAndWrite(parts[0] || addressRemote, parts[1] || portRemote);
    tcpSocket.closed.finally(() => safeCloseWebSocket(webSocket));
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close();
  } catch (e) {}
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      hasIncomingData = true;
      if (webSocket.readyState !== WS_READY_STATE_OPEN) return;
      if (header) {
        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
        header = null;
      } else {
        webSocket.send(chunk);
      }
    }
  })).catch(e => safeCloseWebSocket(webSocket));
  if (!hasIncomingData && retry) retry();
}

// --- LANJUTKAN DENGAN PARSER HEADER (VLESS/SS/Trojan) DARI FILE _WORKER (1).JS ---
// (Copy-paste fungsi parseVlessHeader, parseTrojanHeader, parseSSHeader, dan makeReadableWebSocketStream dari file yang kamu kasih tadi)
