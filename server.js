// server.js — HTTPS forward proxy for FlyVPN
// Handles both HTTP CONNECT tunneling (HTTPS sites) and plain HTTP forwarding

const http = require("http");
const net  = require("net");
const url  = require("url");

const PORT = process.env.PORT || 8080;

// Optional: basic auth to lock down your proxy
// Set PROXY_USER and PROXY_PASS env vars in Fly.io secrets
const AUTH_USER = process.env.PROXY_USER || "";
const AUTH_PASS = process.env.PROXY_PASS || "";

function checkAuth(req) {
  if (!AUTH_USER) return true; // no auth configured — open proxy
  const auth = req.headers["proxy-authorization"] || "";
  if (!auth.startsWith("Basic ")) return false;
  const decoded = Buffer.from(auth.slice(6), "base64").toString();
  const [user, pass] = decoded.split(":");
  return user === AUTH_USER && pass === AUTH_PASS;
}

const server = http.createServer((req, res) => {
  if (!checkAuth(req)) {
    res.writeHead(407, { "Proxy-Authenticate": 'Basic realm="FlyVPN"' });
    return res.end("Proxy authentication required");
  }

  // Forward plain HTTP requests
  const parsed = url.parse(req.url);
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
    console.error("Proxy HTTP error:", err.message);
    res.writeHead(502);
    res.end("Bad gateway");
  });

  req.pipe(proxy, { end: true });
});

// Handle HTTPS CONNECT tunneling
server.on("connect", (req, clientSocket, head) => {
  if (!checkAuth(req)) {
    clientSocket.write("HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm=\"FlyVPN\"\r\n\r\n");
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
  console.log(`FlyVPN proxy listening on port ${PORT}`);
  if (AUTH_USER) {
    console.log(`Auth enabled for user: ${AUTH_USER}`);
  } else {
    console.log("Warning: no auth configured — set PROXY_USER and PROXY_PASS");
  }
});
