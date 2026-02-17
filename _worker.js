import { connect } from "cloudflare:sockets";

// --- KONFIGURASI ---
const PRX_BANK_URL = 'https://raw.githubusercontent.com/h58fmb0344g9h3/p57gdv3j3n0vg334/refs/heads/main/f74bjd2h2ko99f3j5';
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

// Fungsi ambil list dari GitHub (Perbaikan dari aio new.js)
async function getPrxList() {
  try {
    const res = await fetch(PRX_BANK_URL);
    if (res.status == 200) {
      const text = (await res.text()) || "";
      cachedPrxList = text.split("\n").filter(Boolean).map((entry) => {
        const [ip, port, cc, org] = entry.split(",");
        return {
          ip: ip?.trim(),
          port: port?.trim(),
          cc: cc?.trim().toUpperCase(),
          org: org?.trim() || "Unknown",
        };
      });
    }
  } catch (e) {
    console.error("Gagal ambil list proxy");
  }
  return cachedPrxList;
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      if (upgradeHeader === "websocket") {
        const path = url.pathname.replace("/", "").toUpperCase();
        const list = await getPrxList();

        // 1. Cek jika path adalah Kode Negara (2 Huruf)
        let filtered = list.filter(p => p.cc === path);
        
        // 2. Cek jika path adalah IP:PORT manual
        const ipMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (filtered.length > 0) {
          const selected = filtered[Math.floor(Math.random() * filtered.length)];
          prxIP = `${selected.ip}:${selected.port}`;
        } else if (ipMatch) {
          prxIP = ipMatch[1].replace(/[=:-]/, ":");
        } else if (list.length > 0) {
          // Fallback: Jika tidak cocok, ambil acak agar tidak 404
          const random = list[Math.floor(Math.random() * list.length)];
          prxIP = `${random.ip}:${random.port}`;
        }

        if (!prxIP) return new Response("No Proxy Available", { status: 404 });
        return await websocketHandler(request);
      }

      return new Response("Worker is Active. Use /SG, /ID, or /IP:PORT in your VPN app.");
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

// --- CORE HANDLERS (Diambil dari _worker (1).js) ---
async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (isDNS) return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, RELAY_SERVER_UDP);
      
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const protocol = await protocolSniffer(chunk);
      let protocolHeader;

      if (protocol === "Trojan") protocolHeader = readHorseHeader(chunk);
      else if (protocol === "VLESS") protocolHeader = readFlashHeader(chunk);
      else protocolHeader = readSsHeader(chunk);

      if (protocolHeader.isUDP && protocolHeader.portRemote === 53) {
        isDNS = true;
        return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, protocolHeader.version, RELAY_SERVER_UDP);
      }

      handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version);
    }
  })).catch(e => console.error(e));

  return new Response(null, { status: 101, webSocket: client });
}

// --- PARSER FUNCTIONS ---
async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) return "Trojan";
  }
  return (arrayBufferToHex(buffer.slice(1, 17)).match(/^[0-9a-f]{8}[0-9a-f]{4}4/i)) ? "VLESS" : "ss";
}

function readHorseHeader(buffer) {
  const data = buffer.slice(58);
  const view = new DataView(data);
  const addrType = view.getUint8(1);
  let addrLen = 0, addrIdx = 2, addr = "";
  if (addrType === 1) { addrLen = 4; addr = new Uint8Array(data.slice(2, 6)).join("."); }
  else if (addrType === 3) { addrLen = new Uint8Array(data.slice(2, 3))[0]; addrIdx = 3; addr = new TextDecoder().decode(data.slice(3, 3 + addrLen)); }
  const portIdx = addrIdx + addrLen;
  return { addressRemote: addr, portRemote: new DataView(data.slice(portIdx, portIdx + 2)).getUint16(0), rawClientData: data.slice(portIdx + 4), isUDP: view.getUint8(0) === 3 };
}

function readFlashHeader(buffer) {
  const v = new Uint8Array(buffer.slice(0, 1));
  const optL = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optL, 18 + optL + 1))[0];
  const portIdx = 18 + optL + 1;
  const port = new DataView(buffer.slice(portIdx, portIdx + 2)).getUint16(0);
  let addrIdx = portIdx + 2;
  const addrType = new Uint8Array(buffer.slice(addrIdx, addrIdx + 1))[0];
  let addr = "", addrLen = 0;
  if (addrType === 1) { addrLen = 4; addr = new Uint8Array(buffer.slice(addrIdx + 1, addrIdx + 5)).join("."); }
  else if (addrType === 2) { addrLen = new Uint8Array(buffer.slice(addrIdx + 1, addrIdx + 2))[0]; addr = new TextDecoder().decode(buffer.slice(addrIdx + 2, addrIdx + 2 + addrLen)); addrLen++; }
  return { addressRemote: addr, portRemote: port, rawClientData: buffer.slice(addrIdx + 1 + addrLen), version: new Uint8Array([v[0], 0]), isUDP: cmd === 2 };
}

function readSsHeader(buffer) {
  const view = new DataView(buffer);
  const type = view.getUint8(0);
  let len = 0, idx = 1, addr = "";
  if (type === 1) { len = 4; addr = new Uint8Array(buffer.slice(1, 5)).join("."); }
  else if (type === 3) { len = view.getUint8(1); idx = 2; addr = new TextDecoder().decode(buffer.slice(2, 2 + len)); }
  const pIdx = idx + len;
  return { addressRemote: addr, portRemote: new DataView(buffer.slice(pIdx, pIdx + 2)).getUint16(0), rawClientData: buffer.slice(pIdx + 2), isUDP: false };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader) {
  const tcpSocket = connect({ hostname: addressRemote, port: portRemote });
  remoteSocket.value = tcpSocket;
  const writer = tcpSocket.writable.getWriter();
  await writer.write(rawClientData);
  writer.releaseLock();
  remoteSocketToWS(tcpSocket, webSocket, responseHeader);
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, relay) {
  const tcpSocket = connect({ hostname: relay.host, port: relay.port });
  const writer = tcpSocket.writable.getWriter();
  await writer.write(new TextEncoder().encode(`udp:${targetAddress}:${targetPort}|`));
  await writer.write(dataChunk);
  writer.releaseLock();
  remoteSocketToWS(tcpSocket, webSocket, responseHeader);
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader) {
  let header = responseHeader;
  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (webSocket.readyState !== WS_READY_STATE_OPEN) return;
      if (header) {
        webSocket.send(await new Blob([header, chunk]).arrayBuffer());
        header = null;
      } else {
        webSocket.send(chunk);
      }
    }
  })).catch(() => {});
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => controller.enqueue(event.data));
      webSocketServer.addEventListener("close", () => controller.close());
      webSocketServer.addEventListener("error", (err) => controller.error(err));
      const { earlyData } = base64ToArrayBuffer(earlyDataHeader);
      if (earlyData) controller.enqueue(earlyData);
    }
  });
}

function base64ToArrayBuffer(s) {
  if (!s) return { earlyData: null };
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return { earlyData: Uint8Array.from(b, c => c.charCodeAt(0)).buffer };
}

function arrayBufferToHex(b) {
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
