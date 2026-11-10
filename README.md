# Proxy Connector

`proxy_connector.ts` is a general-purpose TypeScript module for parsing proxy configuration strings and opening TCP connections through supported proxy protocols. It also exposes a small UDP relay API for a subset of those protocols.

Use it in a Node.js program whenever you need to connect to a remote TCP service through a supported proxy, or send UDP datagrams through one of the supported UDP relay implementations. It can be integrated into API clients, game/network clients, command-line tools, or other network applications. The module is a client-side connector: it does not run a proxy server or provide a proxy-list service.

## Features

- Parse common proxy URIs and `host:port[:username:password]` entries.
- Establish TCP connections with `connectViaProxy`.
- Create UDP relays with `createUdpRelay` where the proxy protocol implementation supports them.
- Use the returned Node.js socket and relay APIs directly; no separate proxy-list manager is required.

## Protocol support

| Protocol | Parse input | TCP connection | UDP relay |
|---|:---:|:---:|:---:|
| SOCKS5 | Yes | Yes | Yes |
| SOCKS4 | Yes | Yes | Attempts SOCKS `ASSOCIATE`; support depends on the server and library |
| HTTP proxy / CONNECT | Yes | Yes | No |
| HTTPS proxy / CONNECT | Yes | Yes | No |
| Shadowsocks | Yes | Yes | Yes, AEAD ciphers only |
| VLESS | Yes | Yes | Yes |
| VMess | Yes | Yes | Yes |
| Trojan | Yes | Yes | No |
| Hysteria 2 (`hy2`) | Yes | Yes | No |
| Direct TCP | Construct `ProxyInfo` manually | Yes | No |

Protocol support depends on the remote server's configuration and compatibility with the implementation. In particular, the Hysteria 2 TCP path uses HTTP/2 CONNECT with a TLS CONNECT fallback; it is not a general-purpose Hysteria 2 client.

## Requirements

- Node.js with the built-in `net`, `tls`, `crypto`, `url`, `http2`, and `dgram` modules.
- TypeScript and a TypeScript runner/compiler for working with the `.ts` source.
- The [`socks`](https://www.npmjs.com/package/socks) package for SOCKS connections.

Install the runtime dependency:

```bash
npm install socks
```

To run TypeScript files directly during development, install a TypeScript runner and TypeScript:

```bash
npm install --save-dev typescript tsx @types/node
npx tsx example.ts
```

Alternatively, compile the module with your TypeScript build configuration and run the generated JavaScript with Node.js. The module uses Node.js built-in networking and cryptography APIs.

## Supported input formats

`parseProxyString(rawLine)` parses a single line and returns a `ProxyInfo`, or `null` if the line is blank, a comment, malformed, or unsupported. Lines whose first non-whitespace character is `#` are ignored.

```text
socks5://[username:password@]host:port
socks4://[username:password@]host:port
http://[username:password@]host:port
https://[username:password@]host:port
ss://method:password@host:port
vless://uuid@host:port?security=tls&type=ws&path=/path&host=example.com&sni=example.com
vmess://<base64-encoded-json>
trojan://password@host:port?sni=example.com
hysteria2://password@host:port?sni=example.com
hy2://password@host:port?sni=example.com
host:port
host:port:username:password
```

For VLESS, the parser reads `security`, `sni`, `type`, `path`, and `host` from the query string. For VMess, it reads the `add`, `port`, `id`, `aid`, `security`, `tls`, `sni`, `host`, `net`, and `path` JSON fields.

The Shadowsocks parser accepts SIP002-style `ss://` links and a Base64-encoded form containing `method:password@host:port`. UDP relay supports AEAD methods such as `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`, and `chacha20-poly1305`; non-AEAD methods are rejected for UDP.

### Parse a proxy string

```ts
import { parseProxyString } from "./proxy_connector";

const proxy = parseProxyString("socks5://user:password@127.0.0.1:1080");

if (!proxy) {
  throw new Error("Invalid or unsupported proxy string");
}

console.log(`Parsed ${proxy.type} proxy at ${proxy.host}:${proxy.port}`);
```

### Load a proxy list

The module does not read files itself. Read the file in your application and pass each line to the parser:

```ts
import { readFile } from "node:fs/promises";
import { parseProxyString, type ProxyInfo } from "./proxy_connector";

async function loadProxies(filePath: string): Promise<ProxyInfo[]> {
  const contents = await readFile(filePath, "utf8");
  const proxies: ProxyInfo[] = [];

  for (const line of contents.split(/\r?\n/)) {
    const proxy = parseProxyString(line);
    if (proxy) proxies.push(proxy);
  }

  return proxies;
}

const proxies = await loadProxies("./proxies.txt");
console.log(`Loaded ${proxies.length} proxy entries`);
```

Example `proxies.txt`:

```text
# SOCKS5 without authentication
127.0.0.1:1080

# HTTP proxy with authentication
http://user:password@proxy.example:8080

# Shadowsocks
ss://aes-256-gcm:secret@ss.example:8388
```

## TCP connections

Use `connectViaProxy` to connect to a destination. It resolves with a connected `net.Socket`; connection and handshake errors reject the promise.

```ts
import { connectViaProxy, parseProxyString } from "./proxy_connector";

async function main(): Promise<void> {
  const proxy = parseProxyString("socks5://127.0.0.1:1080");
  if (!proxy) throw new Error("Invalid proxy configuration");

  const socket = await connectViaProxy(proxy, "example.com", 443, 6000);

  socket.on("data", (chunk) => {
    console.log("Received:", chunk.toString("utf8"));
  });
  socket.on("error", (error) => {
    console.error("Socket error:", error);
  });
  socket.on("close", () => {
    console.log("Connection closed");
  });

  // Send data through the established tunnel.
  socket.write("example payload");

  // Close the socket when your application is done with it.
  socket.end();
}

main().catch((error: unknown) => {
  console.error("Could not connect:", error);
  process.exitCode = 1;
});
```

### API

```ts
connectViaProxy(
  proxy: ProxyInfo,
  targetHost: string,
  targetPort: number,
  timeoutMs = 6000
): Promise<net.Socket>
```

`timeoutMs` is passed to the proxy-specific connection/handshake implementation where applicable. The direct TCP path does not currently apply this timeout.

### Direct TCP connection

The `direct` type is accepted by `connectViaProxy`, but `parseProxyString` does not parse a `direct://` URI. Construct a `ProxyInfo` object if you want to use the direct branch:

```ts
import { connectViaProxy, type ProxyInfo } from "./proxy_connector";

const direct: ProxyInfo = {
  type: "direct",
  host: "",
  port: 0,
  raw: "direct",
};

const socket = await connectViaProxy(direct, "example.com", 443);
```

## UDP relays

`createUdpRelay` selects the implementation based on `proxy.type`. The relay's `send` method sends a datagram to the specified destination. Set the callbacks to receive replies and relay errors.

```ts
import { createUdpRelay, parseProxyString } from "./proxy_connector";

async function main(): Promise<void> {
  const proxy = parseProxyString("socks5://127.0.0.1:1080");
  if (!proxy) throw new Error("Invalid proxy configuration");

  const relay = await createUdpRelay(proxy, 8000);

  relay.onMessage = (data, host, port) => {
    console.log(`Reply from ${host}:${port}:`, data);
  };
  relay.onError = (error) => {
    console.error("UDP relay error:", error);
  };

  relay.send(Buffer.from("hello"), "example.com", 9000);

  // Close the relay when it is no longer needed.
  // In a real application, call this from your shutdown/cleanup path.
  setTimeout(() => relay.close(), 5000);
}

main().catch((error: unknown) => {
  console.error("Could not create UDP relay:", error);
  process.exitCode = 1;
});
```

### UDP API

```ts
interface UdpRelay {
  send(data: Buffer, targetHost: string, targetPort: number): void;
  close(): void;
  onMessage: ((data: Buffer, host: string, port: number) => void) | null;
  onError: ((err: Error) => void) | null;
}

createUdpRelay(proxy: ProxyInfo, timeoutMs = 8000): Promise<UdpRelay>
```

The timeout applies to relay setup where applicable; it is not a per-datagram response timeout. The `send` method is fire-and-forget and does not return a promise.

For VMess UDP replies, the current relay implementation reports an empty host and port `0` to `onMessage`. SOCKS UDP uses an IPv4 local datagram socket; SOCKS4 does not standardize UDP ASSOCIATE, so its availability depends on the library and server.

## Exported API

| Export | Description |
|---|---|
| `ProxyInfo` | Type describing parsed proxy configuration |
| `UdpRelay` | Interface for sending and receiving relayed datagrams |
| `parseProxyString(rawLine)` | Parse a supported proxy URI or host/port line; returns `null` when it cannot parse the input |
| `connectViaProxy(proxy, targetHost, targetPort, timeoutMs?)` | Open a TCP connection through a proxy |
| `createUdpRelay(proxy, timeoutMs?)` | Create a UDP relay for a supported proxy type |
| `createSocks5UdpRelay(proxy, timeoutMs?)` | Create a SOCKS UDP relay |
| `createShadowsocksUdpRelay(proxy)` | Create a Shadowsocks UDP relay; requires an AEAD cipher |
| `createVlessUdpRelay(proxy, timeoutMs?)` | Create a VLESS UDP relay |
| `createVmessUdpRelay(proxy, timeoutMs?)` | Create a VMess UDP relay |

The protocol-specific UDP functions validate that the supplied `ProxyInfo.type` matches their implementation. `createUdpRelay` rejects unsupported proxy types with an error.

## Error handling and resource cleanup

- Check the parser result before using it; malformed and unsupported input returns `null`.
- Handle rejected promises from `connectViaProxy` and `createUdpRelay`.
- Attach `error` listeners to TCP sockets and assign `relay.onError` for UDP relay errors.
- Call `socket.destroy()`/`socket.end()` and `relay.close()` when resources are no longer needed.
- Proxy strings may contain credentials. Do not commit real proxy links, passwords, or UUIDs, and avoid logging the `raw` field.

## Integrating the module

If `proxy_connector.ts` is in the same directory as your TypeScript file, import the functions and types you need:

```ts
import { connectViaProxy, parseProxyString, type ProxyInfo } from "./proxy_connector";
```

If your application uses a different module layout or build system, adjust the import path and TypeScript configuration accordingly. The module is designed to be usable on its own.

For example, a small project can keep the connector and its entry point together:

```bash
my-app/
  proxy_connector.ts
  example.ts
  package.json
```

Then run the entry point with `tsx`:

```bash
npx tsx example.ts
```
