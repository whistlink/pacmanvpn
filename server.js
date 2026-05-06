// server.js — PacmanVPN proxy for Render.com

const http = require("http");
const net  = require("net");
const url  = require("url");

const PORT      = process.env.PORT      || 8080;
const AUTH_USER = process.env.PROXY_USER || "";
const AUTH_PASS = process.env.PROXY_PASS || "";

function checkAuth(req) {
  if (!AUTH_USER) return true;
  const auth = req.headers["proxy-authorization"] || "";
  if (!auth.startsWith("Basic ")) return false;
  const decoded = Buffer.from(auth.slice(6), "base64").toString();
  const [user, pass] = decoded.split(":");
  return user === AUTH_USER && pass === AUTH_PASS;
}

function getPacFile(host) {
  return `function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || host === "localhost" || host === "127.0.0.1") {
    return "DIRECT";
  }
  return "HTTPS ${host}:443";
}`;
}

const server = http.createServer((req, res) => {
  // Health check
  if (req.url === "/" || req.url === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("PacmanVPN proxy running");
  }

  // Serve PAC file
  if (req.url === "/pac" || req.url === "/proxy.pac") {
    const host = req.headers.host || "localhost";
    const pac  = getPacFile(host);
    res.writeHead(200, {
      "Content-Type":  "application/x-ns-proxy-autoconfig",
      "Cache-Control": "no-cache"
    });
    return res.end(pac);
  }

  if (!checkAuth(req)) {
    res.writeHead(407, { "Proxy-Authenticate": 'Basic realm="PacmanVPN"' });
    return res.end("Proxy authentication required");
  }

  // Forward plain HTTP requests
  const parsed  = url.parse(req.url);
  const options = {
    hostname: parsed.hostname,
    port:     parsed.port || 80,
    path:     parsed.path,
    method:   req.method,
    headers:  { ...req.headers, host: parsed.hostname }
  };
  delete options.headers["proxy-authorization"];

  const proxy = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxy.on("error", (err) => {
    console.error("HTTP proxy error:", err.message);
    res.writeHead(502);
    res.end("Bad gateway");
  });

  req.pipe(proxy, { end: true });
});

// CONNECT tunneling for HTTPS
server.on("connect", (req, clientSocket, head) => {
  if (!checkAuth(req)) {
    clientSocket.write("HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm=\"PacmanVPN\"\r\n\r\n");
    return clientSocket.destroy();
  }

  const [hostname, portStr] = req.url.split(":");
  const port = parseInt(portStr) || 443;

  console.log(`CONNECT tunnel: ${hostname}:${port}`);

  const serverSocket = net.connect(port, hostname, () => {
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on("error", (err) => {
    console.error("Tunnel error:", err.message);
    clientSocket.destroy();
  });

  clientSocket.on("error", () => serverSocket.destroy());
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`PacmanVPN proxy listening on port ${PORT}`);
  if (AUTH_USER) console.log(`Auth enabled for user: ${AUTH_USER}`);
  else console.log("Warning: no auth configured");
});
