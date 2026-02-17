import { connect } from "cloudflare:sockets";

const proxyListURL = 'https://gh-proxy.com/https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt';

let cachedProxyList = [];
let proxyIP = "";

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      // Load data jika cache kosong
      if (cachedProxyList.length === 0) {
        const response = await fetch(proxyListURL);
        const text = await response.text();
        cachedProxyList = text.split("\n")
          .filter(line => line.includes(','))
          .map(line => {
            const parts = line.split(",");
            return {
              ip: parts[0]?.trim(),
              port: parts[1]?.trim(),
              cc: parts[2]?.trim().toUpperCase()
            };
          });
      }

      if (upgradeHeader === "websocket") {
        const path = url.pathname.replace(/^\//, "");
        
        // Logika pilih proxy berdasarkan Negara (Contoh: /SG)
        if (path.length === 2) {
          const filtered = cachedProxyList.filter(p => p.cc === path.toUpperCase());
          if (filtered.length > 0) {
            const selected = filtered[Math.floor(Math.random() * filtered.length)];
            proxyIP = `${selected.ip}:${selected.port}`;
          }
        } 
        // Logika IP:Port manual
        else if (path.includes(":") || path.includes("=")) {
          proxyIP = path.replace(/[=]/, ":");
        }

        if (!proxyIP) {
          return new Response("No Proxy Selected", { status: 400 });
        }

        return await websocketHandler(request);
      }

      return new Response("Worker is Running", { status: 200 });
    } catch (err) {
      return new Response(`Error: ${err.message}`, { status: 500 });
    }
  }
};

// ... (Sisa fungsi websocketHandler, protocolSniffer, dll sama seperti sebelumnya)
