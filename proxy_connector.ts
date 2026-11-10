import * as net from "net";
import * as tls from "tls";
import * as crypto from "crypto";
import * as url from "url";
import * as http2 from "http2";
import * as dgram from "dgram";
import { SocksClient } from "socks";

export interface ProxyInfo {
  type: "socks5" | "socks4" | "http" | "https" | "shadowsocks" | "vless" | "direct" | "vmess" | "trojan" | "hysteria2";
  host: string;
  port: number;
  username?: string;
  password?: string;
  cipherMethod?: string;
  uuid?: string;
  security?: "none" | "tls";
  sni?: string;
  transport?: "tcp" | "ws";
  wsPath?: string;
  wsHost?: string;
  vmessAlterId?: number;
  vmessSecurity?: string;
  trojanPassword?: string;
  hysteria2Password?: string;
  hysteria2Obfs?: string;
  hysteria2ObfsPassword?: string;
  hysteria2Insecure?: boolean;
  raw: string;
}

export interface UdpRelay {
  send(data: Buffer, targetHost: string, targetPort: number): void;
  close(): void;
  onMessage: ((data: Buffer, host: string, port: number) => void) | null;
  onError: ((err: Error) => void) | null;
}

export function parseProxyString(rawLine: string): ProxyInfo | null {
  const line = rawLine.trim();
  if (!line || line.startsWith("#")) return null;

  try {
    if (line.startsWith("vless://")) {
      const parsed = new url.URL(line);
      const uuid = decodeURIComponent(parsed.username || "");
      const host = parsed.hostname;
      const port = parseInt(parsed.port || "443", 10);
      const query = parsed.searchParams;
      return {
        type: "vless",
        host,
        port,
        uuid,
        security: (query.get("security") === "tls" ? "tls" : "none") as "none" | "tls",
        sni: query.get("sni") || host,
        transport: (query.get("type") === "ws" ? "ws" : "tcp") as "tcp" | "ws",
        wsPath: query.get("path") || "/",
        wsHost: query.get("host") || host,
        raw: line,
      };
    }

    if (line.startsWith("vmess://")) {
      const b64 = line.slice(8).replace(/#.*$/, "");
      let json: any;
      try {
        json = JSON.parse(Buffer.from(b64, "base64").toString("utf-8"));
      } catch {
        return null;
      }
      const host = json.add || "";
      const port = parseInt(json.port || "443", 10);
      const uuid = json.id || "";
      if (host && port && uuid) {
        return {
          type: "vmess",
          host,
          port,
          uuid,
          vmessAlterId: parseInt(json.aid || "0", 10),
          vmessSecurity: json.security || "auto",
          security: (json.tls === "tls" ? "tls" : "none") as "none" | "tls",
          sni: json.sni || json.host || host,
          transport: (json.net === "ws" ? "ws" : "tcp") as "tcp" | "ws",
          wsPath: json.path || "/",
          wsHost: json.host || host,
          raw: line,
        };
      }
    }

    if (line.startsWith("hysteria2://") || line.startsWith("hy2://")) {
      const parsed = new url.URL(line);
      const password = decodeURIComponent(parsed.username || "");
      const host = parsed.hostname;
      const port = parseInt(parsed.port || "443", 10);
      const query = parsed.searchParams;
      if (host && port && password) {
        return {
          type: "hysteria2",
          host,
          port,
          hysteria2Password: password,
          hysteria2Obfs: query.get("obfs") || undefined,
          hysteria2ObfsPassword: query.get("obfs-password") || undefined,
          hysteria2Insecure: query.get("insecure") === "1" || query.get("allowInsecure") === "1",
          security: "tls",
          sni: query.get("sni") || host,
          raw: line,
        };
      }
    }

    if (line.startsWith("trojan://")) {
      const parsed = new url.URL(line);
      const trojanPassword = decodeURIComponent(parsed.username || "");
      const host = parsed.hostname;
      const port = parseInt(parsed.port || "443", 10);
      const query = parsed.searchParams;
      if (host && port && trojanPassword) {
        return {
          type: "trojan",
          host,
          port,
          trojanPassword,
          security: "tls",
          sni: query.get("sni") || host,
          transport: (query.get("type") === "ws" ? "ws" : "tcp") as "tcp" | "ws",
          wsPath: query.get("path") || "/",
          wsHost: query.get("host") || host,
          raw: line,
        };
      }
    }

    if (line.startsWith("ss://")) {
      let content = line.slice(5);
      const hashIdx = content.indexOf("#");
      if (hashIdx !== -1) content = content.substring(0, hashIdx);

      let method = "aes-256-gcm";
      let password = "";
      let host = "";
      let port = 8388;

      if (content.includes("@")) {
        const [userInfoPart, hostPortPart] = content.split("@");
        const [h, p] = hostPortPart.split(":");
        host = h;
        port = parseInt(p, 10) || 8388;
        let decodedUser = userInfoPart;
        try {
          if (!userInfoPart.includes(":")) {
            decodedUser = Buffer.from(userInfoPart, "base64").toString("utf-8");
          }
        } catch {
          decodedUser = userInfoPart;
        }
        const colonIdx = decodedUser.indexOf(":");
        if (colonIdx !== -1) {
          method = decodedUser.substring(0, colonIdx);
          password = decodedUser.substring(colonIdx + 1);
        } else {
          password = decodedUser;
        }
      } else {
        try {
          const decoded = Buffer.from(content, "base64").toString("utf-8");
          if (decoded.includes("@")) {
            const [u, hp] = decoded.split("@");
            const [h, p] = hp.split(":");
            host = h;
            port = parseInt(p, 10) || 8388;
            const colonIdx = u.indexOf(":");
            if (colonIdx !== -1) {
              method = u.substring(0, colonIdx);
              password = u.substring(colonIdx + 1);
            } else {
              password = u;
            }
          }
        } catch {}
      }

      if (host && port) {
        return {
          type: "shadowsocks",
          host,
          port,
          cipherMethod: method.toLowerCase(),
          password,
          raw: line,
        };
      }
    }

    if (line.startsWith("socks5://") || line.startsWith("socks4://") || line.startsWith("http://") || line.startsWith("https://")) {
      const parsed = new url.URL(line);
      const proto = parsed.protocol.replace(":", "");
      let proxyType: ProxyInfo["type"];
      if (proto === "socks4") proxyType = "socks4";
      else if (proto === "https") proxyType = "https";
      else if (proto === "http") proxyType = "http";
      else proxyType = "socks5";
      return {
        type: proxyType,
        host: parsed.hostname,
        port: parseInt(parsed.port || (proto === "http" || proto === "https" ? "80" : "1080"), 10),
        username: parsed.username ? decodeURIComponent(parsed.username) : undefined,
        password: parsed.password ? decodeURIComponent(parsed.password) : undefined,
        raw: line,
      };
    }

    const parts = line.split(":");
    if (parts.length >= 2) {
      const host = parts[0];
      const port = parseInt(parts[1], 10);
      if (host && !isNaN(port)) {
        return {
          type: "socks5",
          host,
          port,
          username: parts[2],
          password: parts[3],
          raw: line,
        };
      }
    }
  } catch {}
  return null;
}

function kdf(password: string, keyLen: number): Buffer {
  let result = Buffer.alloc(0);
  let prev = Buffer.alloc(0);
  while (result.length < keyLen) {
    const md5 = crypto.createHash("md5");
    md5.update(prev);
    md5.update(Buffer.from(password, "utf-8"));
    prev = md5.digest();
    result = Buffer.concat([result, prev]);
  }
  return result.subarray(0, keyLen);
}

function hkdfSubkey(key: Buffer, salt: Buffer, keyLen: number): Buffer {
  return Buffer.from(crypto.hkdfSync("sha1", key, salt, Buffer.from("ss-subkey"), keyLen));
}

function getShadowsocksKeySize(method: string): { keySize: number; saltSize: number; isAEAD: boolean } {
  switch (method) {
    case "aes-128-gcm": return { keySize: 16, saltSize: 16, isAEAD: true };
    case "aes-192-gcm": return { keySize: 24, saltSize: 24, isAEAD: true };
    case "aes-256-gcm":
    case "chacha20-poly1305":
    case "chacha20-ietf-poly1305": return { keySize: 32, saltSize: 32, isAEAD: true };
    case "aes-256-cfb":
    case "aes-256-ctr":
    case "chacha20": return { keySize: 32, saltSize: 16, isAEAD: false };
    case "aes-128-cfb":
    case "aes-128-ctr": return { keySize: 16, saltSize: 16, isAEAD: false };
    default: return { keySize: 32, saltSize: 32, isAEAD: true };
  }
}

function createShadowsocksSocket(
  rawSocket: net.Socket,
  proxy: ProxyInfo,
  targetHost: string,
  targetPort: number,
  onReady: (sock: net.Socket) => void,
  onError: (err: Error) => void
): void {
  const method = proxy.cipherMethod || "aes-256-gcm";
  const password = proxy.password || "";
  const { keySize, saltSize, isAEAD } = getShadowsocksKeySize(method);
  const masterKey = kdf(password, keySize);

  let addrBuf: Buffer;
  if (net.isIPv4(targetHost)) {
    const ipParts = targetHost.split(".").map(x => parseInt(x, 10));
    addrBuf = Buffer.alloc(1 + 4 + 2);
    addrBuf[0] = 0x01;
    Buffer.from(ipParts).copy(addrBuf, 1);
    addrBuf.writeUInt16BE(targetPort, 5);
  } else if (net.isIPv6(targetHost)) {
    addrBuf = Buffer.alloc(1 + 16 + 2);
    addrBuf[0] = 0x04;
    addrBuf.writeUInt16BE(targetPort, 17);
  } else {
    const hostBytes = Buffer.from(targetHost, "utf-8");
    addrBuf = Buffer.alloc(1 + 1 + hostBytes.length + 2);
    addrBuf[0] = 0x03;
    addrBuf[1] = hostBytes.length;
    hostBytes.copy(addrBuf, 2);
    addrBuf.writeUInt16BE(targetPort, 2 + hostBytes.length);
  }

  if (isAEAD) {
    const sendSalt = crypto.randomBytes(saltSize);
    const sendSubkey = hkdfSubkey(masterKey, sendSalt, keySize);
    let sendNonce = 0;
    let recvSalt: Buffer | null = null;
    let recvSubkey: Buffer | null = null;
    let recvNonce = 0;
    let recvBuf = Buffer.alloc(0);

    const getNonceBuf = (nonce: number): Buffer => {
      const b = Buffer.alloc(12, 0);
      b.writeUInt32LE(nonce, 0);
      return b;
    };

    const encryptAEADChunk = (chunk: Buffer): Buffer => {
      const cipherName = method.startsWith("chacha20") ? "chacha20-poly1305" : method;
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(chunk.length, 0);
      const cipher1 = crypto.createCipheriv(cipherName, sendSubkey, getNonceBuf(sendNonce++), { authTagLength: 16 } as any) as crypto.CipherGCM;
      const encLen = Buffer.concat([cipher1.update(lenBuf), cipher1.final(), cipher1.getAuthTag()]);
      const cipher2 = crypto.createCipheriv(cipherName, sendSubkey, getNonceBuf(sendNonce++), { authTagLength: 16 } as any) as crypto.CipherGCM;
      const encPayload = Buffer.concat([cipher2.update(chunk), cipher2.final(), cipher2.getAuthTag()]);
      return Buffer.concat([encLen, encPayload]);
    };

    const clientSocket = new net.Socket();
    rawSocket.on("error", (e) => clientSocket.emit("error", e));
    rawSocket.on("close", (hadErr) => clientSocket.emit("close", hadErr));
    rawSocket.write(Buffer.concat([sendSalt, encryptAEADChunk(addrBuf)]));

    rawSocket.on("data", (data: Buffer) => {
      recvBuf = Buffer.concat([recvBuf, data]);
      if (!recvSalt) {
        if (recvBuf.length < saltSize) return;
        recvSalt = recvBuf.subarray(0, saltSize);
        recvBuf = recvBuf.subarray(saltSize);
        recvSubkey = hkdfSubkey(masterKey, recvSalt, keySize);
      }
      const cipherName = method.startsWith("chacha20") ? "chacha20-poly1305" : method;
      while (recvBuf.length > 0) {
        if (recvBuf.length < 18) break;
        const encLenBuf = recvBuf.subarray(0, 2);
        const lenTag = recvBuf.subarray(2, 18);
        let payloadLen = 0;
        try {
          const decipher1 = crypto.createDecipheriv(cipherName, recvSubkey!, getNonceBuf(recvNonce++), { authTagLength: 16 } as any) as crypto.DecipherGCM;
          decipher1.setAuthTag(lenTag);
          const decLen = Buffer.concat([decipher1.update(encLenBuf), decipher1.final()]);
          payloadLen = decLen.readUInt16BE(0);
        } catch (e: any) {
          rawSocket.destroy();
          clientSocket.emit("error", new Error(`SS AEAD decrypt len error: ${e.message}`));
          return;
        }
        if (recvBuf.length < 18 + payloadLen + 16) {
          recvNonce--;
          break;
        }
        const encPayload = recvBuf.subarray(18, 18 + payloadLen);
        const payloadTag = recvBuf.subarray(18 + payloadLen, 18 + payloadLen + 16);
        recvBuf = recvBuf.subarray(18 + payloadLen + 16);
        try {
          const decipher2 = crypto.createDecipheriv(cipherName, recvSubkey!, getNonceBuf(recvNonce++), { authTagLength: 16 } as any) as crypto.DecipherGCM;
          decipher2.setAuthTag(payloadTag);
          const decPayload = Buffer.concat([decipher2.update(encPayload), decipher2.final()]);
          clientSocket.emit("data", decPayload);
        } catch (e: any) {
          rawSocket.destroy();
          clientSocket.emit("error", new Error(`SS AEAD decrypt payload error: ${e.message}`));
          return;
        }
      }
    });

    clientSocket.write = function (chunk: any, cb?: any): boolean {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      return rawSocket.write(encryptAEADChunk(buf), cb);
    };
    clientSocket.destroy = function (err?: Error): net.Socket {
      rawSocket.destroy(err);
      return this;
    };
    clientSocket.end = function (data?: any, cb?: any): net.Socket {
      if (data) this.write(data);
      rawSocket.end(cb);
      return this;
    };
    onReady(clientSocket);
  } else {
    const iv = crypto.randomBytes(saltSize);
    const cipher = crypto.createCipheriv(method, masterKey, iv);
    let decipher: crypto.Decipheriv | null = null;
    let recvBuf = Buffer.alloc(0);
    const clientSocket = new net.Socket();
    rawSocket.on("error", (e) => clientSocket.emit("error", e));
    rawSocket.on("close", (hadErr) => clientSocket.emit("close", hadErr));
    rawSocket.write(Buffer.concat([iv, cipher.update(addrBuf)]));
    rawSocket.on("data", (data: Buffer) => {
      if (!decipher) {
        recvBuf = Buffer.concat([recvBuf, data]);
        if (recvBuf.length < saltSize) return;
        const recvIV = recvBuf.subarray(0, saltSize);
        const rest = recvBuf.subarray(saltSize);
        decipher = crypto.createDecipheriv(method, masterKey, recvIV);
        if (rest.length > 0) clientSocket.emit("data", decipher.update(rest));
      } else {
        clientSocket.emit("data", decipher.update(data));
      }
    });
    clientSocket.write = function (chunk: any, cb?: any): boolean {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      return rawSocket.write(cipher.update(buf), cb);
    };
    clientSocket.destroy = function (err?: Error): net.Socket {
      rawSocket.destroy(err);
      return this;
    };
    onReady(clientSocket);
  }
}

function uuidToBuffer(uuidStr: string): Buffer {
  return Buffer.from(uuidStr.replace(/-/g, ""), "hex");
}

function buildVlessRequestHeader(uuid: string, targetHost: string, targetPort: number, isUdp = false): Buffer {
  const uuidBuf = uuidToBuffer(uuid);
  let addrType = 0x01;
  let addrBuf: Buffer;
  if (net.isIPv4(targetHost)) {
    addrType = 0x01;
    addrBuf = Buffer.from(targetHost.split(".").map(x => parseInt(x, 10)));
  } else if (net.isIPv6(targetHost)) {
    addrType = 0x03;
    addrBuf = Buffer.alloc(16);
  } else {
    addrType = 0x02;
    const hostBytes = Buffer.from(targetHost, "utf-8");
    addrBuf = Buffer.concat([Buffer.from([hostBytes.length]), hostBytes]);
  }
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(targetPort, 0);
  return Buffer.concat([
    Buffer.from([0x00]),
    uuidBuf,
    Buffer.from([0x00, isUdp ? 0x02 : 0x01]),
    portBuf,
    Buffer.from([addrType]),
    addrBuf,
  ]);
}

function createVlessSocket(
  proxy: ProxyInfo,
  targetHost: string,
  targetPort: number,
  timeoutMs: number,
  isUdp = false
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("VLESS connection timeout")), timeoutMs);
    const cleanup = () => { if (timer) { clearTimeout(timer); timer = null; } };
    const isTls = proxy.security === "tls";
    const transport = proxy.transport || "tcp";
    const vlessHeader = buildVlessRequestHeader(proxy.uuid || "", targetHost, targetPort, isUdp);

    let rawSocket: net.Socket = isTls
      ? tls.connect({ host: proxy.host, port: proxy.port, servername: proxy.sni || proxy.host, rejectUnauthorized: false })
      : net.createConnection({ host: proxy.host, port: proxy.port });

    rawSocket.on("error", (err) => { cleanup(); reject(err); });

    if (transport === "ws") {
      rawSocket.on("connect", () => {
        const wsKey = crypto.randomBytes(16).toString("base64");
        const wsReq =
          `GET ${proxy.wsPath || "/"} HTTP/1.1\r\n` +
          `Host: ${proxy.wsHost || proxy.host}\r\n` +
          `Upgrade: websocket\r\n` +
          `Connection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${wsKey}\r\n` +
          `Sec-WebSocket-Version: 13\r\n\r\n`;
        rawSocket.write(wsReq);

        let httpHeadersReceived = false;
        let httpBuffer = "";
        const onDataHttp = (chunk: Buffer) => {
          if (!httpHeadersReceived) {
            httpBuffer += chunk.toString("binary");
            const headerEnd = httpBuffer.indexOf("\r\n\r\n");
            if (headerEnd !== -1) {
              httpHeadersReceived = true;
              rawSocket.removeListener("data", onDataHttp);
              const maskKey = crypto.randomBytes(4);
              const maskedPayload = Buffer.alloc(vlessHeader.length);
              for (let i = 0; i < vlessHeader.length; i++) maskedPayload[i] = vlessHeader[i] ^ maskKey[i % 4];
              let frameBuf: Buffer;
              if (vlessHeader.length <= 125) {
                frameBuf = Buffer.concat([Buffer.from([0x82, 0x80 | vlessHeader.length]), maskKey, maskedPayload]);
              } else {
                const lenBuf = Buffer.alloc(2);
                lenBuf.writeUInt16BE(vlessHeader.length, 0);
                frameBuf = Buffer.concat([Buffer.from([0x82, 0x80 | 126]), lenBuf, maskKey, maskedPayload]);
              }
              rawSocket.write(frameBuf);

              let vlessRespRead = false;
              const vlessClientSocket = new net.Socket();
              vlessClientSocket.write = function (data: any, cb?: any): boolean {
                const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
                const mKey = crypto.randomBytes(4);
                const mData = Buffer.alloc(b.length);
                for (let i = 0; i < b.length; i++) mData[i] = b[i] ^ mKey[i % 4];
                let wsHeader: Buffer;
                if (b.length <= 125) {
                  wsHeader = Buffer.concat([Buffer.from([0x82, 0x80 | b.length]), mKey]);
                } else if (b.length <= 65535) {
                  const lb = Buffer.alloc(2);
                  lb.writeUInt16BE(b.length, 0);
                  wsHeader = Buffer.concat([Buffer.from([0x82, 0x80 | 126]), lb, mKey]);
                } else {
                  const lb = Buffer.alloc(8);
                  lb.writeBigUInt64BE(BigInt(b.length), 0);
                  wsHeader = Buffer.concat([Buffer.from([0x82, 0x80 | 127]), lb, mKey]);
                }
                return rawSocket.write(Buffer.concat([wsHeader, mData]), cb);
              };
              vlessClientSocket.destroy = function (e?: Error) { rawSocket.destroy(e); return this; };

              rawSocket.on("data", (wsChunk: Buffer) => {
                let pos = 0;
                while (pos < wsChunk.length) {
                  if (pos + 2 > wsChunk.length) break;
                  pos++;
                  const b1 = wsChunk[pos++];
                  let pLen = b1 & 0x7f;
                  if (pLen === 126) {
                    if (pos + 2 > wsChunk.length) break;
                    pLen = wsChunk.readUInt16BE(pos);
                    pos += 2;
                  } else if (pLen === 127) {
                    if (pos + 8 > wsChunk.length) break;
                    pLen = Number(wsChunk.readBigUInt64BE(pos));
                    pos += 8;
                  }
                  if (pos + pLen > wsChunk.length) break;
                  let payload = wsChunk.subarray(pos, pos + pLen);
                  pos += pLen;
                  if (!vlessRespRead) {
                    if (payload.length >= 2) {
                      const addonLen = payload[1];
                      payload = payload.subarray(2 + addonLen);
                      vlessRespRead = true;
                    }
                  }
                  if (payload.length > 0) vlessClientSocket.emit("data", payload);
                }
              });
              cleanup();
              resolve(vlessClientSocket);
            }
          }
        };
        rawSocket.on("data", onDataHttp);
      });
    } else {
      const onConnect = () => {
        rawSocket.write(vlessHeader);
        let vlessRespRead = false;
        let pendingBuf = Buffer.alloc(0);
        const onInitialData = (chunk: Buffer) => {
          if (!vlessRespRead) {
            pendingBuf = Buffer.concat([pendingBuf, chunk]);
            if (pendingBuf.length >= 2) {
              const addonLen = pendingBuf[1];
              if (pendingBuf.length >= 2 + addonLen) {
                vlessRespRead = true;
                rawSocket.removeListener("data", onInitialData);
                const rest = pendingBuf.subarray(2 + addonLen);
                cleanup();
                resolve(rawSocket);
                if (rest.length > 0) rawSocket.emit("data", rest);
              }
            }
          }
        };
        rawSocket.on("data", onInitialData);
      };
      if (isTls) (rawSocket as tls.TLSSocket).on("secureConnect", onConnect);
      else rawSocket.on("connect", onConnect);
    }
  });
}

function createHttpConnectSocket(proxy: ProxyInfo, targetHost: string, targetPort: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("HTTP proxy timeout")), timeoutMs);
    const cleanup = () => { if (timer) { clearTimeout(timer); timer = null; } };
    const sock = net.createConnection({ host: proxy.host, port: proxy.port }, () => {
      let authHeader = "";
      if (proxy.username && proxy.password) {
        const creds = Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64");
        authHeader = `Proxy-Authorization: Basic ${creds}\r\n`;
      }
      const req = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${authHeader}Proxy-Connection: Keep-Alive\r\n\r\n`;
      sock.write(req);
    });
    sock.on("error", (e) => { cleanup(); reject(e); });
    let buffer = "";
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("binary");
      const endOfHeader = buffer.indexOf("\r\n\r\n");
      if (endOfHeader !== -1) {
        sock.removeListener("data", onData);
        cleanup();
        const statusLine = buffer.split("\r\n")[0];
        if (statusLine.includes("200")) {
          const rest = Buffer.from(buffer.substring(endOfHeader + 4), "binary");
          resolve(sock);
          if (rest.length > 0) sock.emit("data", rest);
        } else {
          sock.destroy();
          reject(new Error(`HTTP CONNECT failed: ${statusLine}`));
        }
      }
    };
    sock.on("data", onData);
  });
}

function buildTrojanRequest(password: string, targetHost: string, targetPort: number): Buffer {
  const sha256Hex = crypto.createHash("sha256").update(password).digest("hex");
  let addrBuf: Buffer;
  if (net.isIPv4(targetHost)) {
    const ipParts = targetHost.split(".").map(x => parseInt(x, 10));
    addrBuf = Buffer.alloc(1 + 4);
    addrBuf[0] = 0x01;
    Buffer.from(ipParts).copy(addrBuf, 1);
  } else {
    const hostBytes = Buffer.from(targetHost, "utf-8");
    addrBuf = Buffer.alloc(1 + 1 + hostBytes.length);
    addrBuf[0] = 0x03;
    addrBuf[1] = hostBytes.length;
    hostBytes.copy(addrBuf, 2);
  }
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(targetPort, 0);
  return Buffer.concat([Buffer.from(sha256Hex, "utf-8"), Buffer.from("\r\n"), Buffer.from([0x01]), addrBuf, portBuf, Buffer.from("\r\n")]);
}

function createTrojanSocket(proxy: ProxyInfo, targetHost: string, targetPort: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("Trojan connection timeout")), timeoutMs);
    const cleanup = () => { if (timer) { clearTimeout(timer); timer = null; } };
    const transport = proxy.transport || "tcp";
    const tlsSocket = tls.connect({
      host: proxy.host,
      port: proxy.port,
      servername: proxy.sni || proxy.host,
      rejectUnauthorized: false,
    });
    tlsSocket.on("error", (err) => { cleanup(); reject(err); });

    if (transport === "ws") {
      tlsSocket.on("secureConnect", () => {
        const wsKey = crypto.randomBytes(16).toString("base64");
        const wsReq =
          `GET ${proxy.wsPath || "/"} HTTP/1.1\r\n` +
          `Host: ${proxy.wsHost || proxy.host}\r\n` +
          `Upgrade: websocket\r\n` +
          `Connection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${wsKey}\r\n` +
          `Sec-WebSocket-Version: 13\r\n\r\n`;
        tlsSocket.write(wsReq);
        let httpBuf = "";
        let httpDone = false;
        const onWsData = (chunk: Buffer) => {
          if (!httpDone) {
            httpBuf += chunk.toString("binary");
            const end = httpBuf.indexOf("\r\n\r\n");
            if (end !== -1) {
              httpDone = true;
              tlsSocket.removeListener("data", onWsData);
              const trojanReq = buildTrojanRequest(proxy.trojanPassword || "", targetHost, targetPort);
              const mKey = crypto.randomBytes(4);
              const masked = Buffer.alloc(trojanReq.length);
              for (let i = 0; i < trojanReq.length; i++) masked[i] = trojanReq[i] ^ mKey[i % 4];
              let wsFrame: Buffer;
              if (trojanReq.length <= 125) {
                wsFrame = Buffer.concat([Buffer.from([0x82, 0x80 | trojanReq.length]), mKey, masked]);
              } else {
                const lb = Buffer.alloc(2);
                lb.writeUInt16BE(trojanReq.length, 0);
                wsFrame = Buffer.concat([Buffer.from([0x82, 0x80 | 126]), lb, mKey, masked]);
              }
              tlsSocket.write(wsFrame);
              const clientSocket = new net.Socket();
              clientSocket.write = function (data: any, cb?: any): boolean {
                const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
                const mk = crypto.randomBytes(4);
                const md = Buffer.alloc(b.length);
                for (let i = 0; i < b.length; i++) md[i] = b[i] ^ mk[i % 4];
                let wh: Buffer;
                if (b.length <= 125) {
                  wh = Buffer.concat([Buffer.from([0x82, 0x80 | b.length]), mk]);
                } else if (b.length <= 65535) {
                  const l = Buffer.alloc(2);
                  l.writeUInt16BE(b.length, 0);
                  wh = Buffer.concat([Buffer.from([0x82, 0x80 | 126]), l, mk]);
                } else {
                  const l = Buffer.alloc(8);
                  l.writeBigUInt64BE(BigInt(b.length), 0);
                  wh = Buffer.concat([Buffer.from([0x82, 0x80 | 127]), l, mk]);
                }
                return tlsSocket.write(Buffer.concat([wh, md]), cb);
              };
              clientSocket.destroy = function (e?: Error) { tlsSocket.destroy(e); return this; };
              tlsSocket.on("data", (wsChunk: Buffer) => {
                let pos = 0;
                while (pos < wsChunk.length) {
                  if (pos + 2 > wsChunk.length) break;
                  pos++;
                  const b1 = wsChunk[pos++];
                  let pLen = b1 & 0x7f;
                  if (pLen === 126) {
                    if (pos + 2 > wsChunk.length) break;
                    pLen = wsChunk.readUInt16BE(pos);
                    pos += 2;
                  } else if (pLen === 127) {
                    if (pos + 8 > wsChunk.length) break;
                    pLen = Number(wsChunk.readBigUInt64BE(pos));
                    pos += 8;
                  }
                  if (pos + pLen > wsChunk.length) break;
                  const payload = wsChunk.subarray(pos, pos + pLen);
                  pos += pLen;
                  if (payload.length > 0) clientSocket.emit("data", payload);
                }
              });
              cleanup();
              resolve(clientSocket);
            }
          }
        };
        tlsSocket.on("data", onWsData);
      });
    } else {
      tlsSocket.on("secureConnect", () => {
        const trojanReq = buildTrojanRequest(proxy.trojanPassword || "", targetHost, targetPort);
        tlsSocket.write(trojanReq);
        cleanup();
        resolve(tlsSocket);
      });
    }
  });
}

function buildVmessRequestHeader(uuid: string, targetHost: string, targetPort: number, securityType: string, isUdp = false) {
  const requestKey = crypto.randomBytes(16);
  const requestIV = crypto.randomBytes(16);
  const responseAuth = crypto.randomBytes(1)[0];
  const opts = 0x01;
  let secByte = 0x03;
  if (securityType === "chacha20-poly1305") secByte = 0x04;
  else if (securityType === "none") secByte = 0x05;
  const paddingLen = Math.floor(Math.random() * 16);
  const secAndPadding = (secByte << 4) | paddingLen;
  const cmd = isUdp ? 0x02 : 0x01;
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(targetPort, 0);
  let addrType: number;
  let addrBuf: Buffer;
  if (net.isIPv4(targetHost)) {
    addrType = 0x01;
    addrBuf = Buffer.from(targetHost.split(".").map(x => parseInt(x, 10)));
  } else {
    addrType = 0x02;
    const hostBytes = Buffer.from(targetHost, "utf-8");
    addrBuf = Buffer.concat([Buffer.from([hostBytes.length]), hostBytes]);
  }
  const padding = crypto.randomBytes(paddingLen);
  const innerParts = [
    Buffer.from([1]), requestIV, requestKey, Buffer.from([responseAuth]),
    Buffer.from([opts]), Buffer.from([secAndPadding]), Buffer.from([0x00]),
    Buffer.from([cmd]), portBuf, Buffer.from([addrType]), addrBuf, padding,
  ];
  const innerHeader = Buffer.concat(innerParts);
  let hash = 0x811c9dc5 >>> 0;
  for (let i = 0; i < innerHeader.length; i++) {
    hash ^= innerHeader[i];
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  const fnv = Buffer.alloc(4);
  fnv.writeUInt32BE(hash, 0);
  const fullInner = Buffer.concat([innerHeader, fnv]);
  const uuidBuf = Buffer.from(uuid.replace(/-/g, ""), "hex");
  const now = Math.floor(Date.now() / 1000);
  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigUInt64BE(BigInt(now), 0);
  const authInfo = crypto.createHmac("md5", uuidBuf).update(timeBuf).digest();
  const cmdKey = crypto.createHash("md5").update(uuidBuf).update(Buffer.from("c48619fe-8f02-49e0-b9e9-edf763e17e21")).digest();
  const cmdIV = crypto.createHash("md5").update(timeBuf).update(timeBuf).update(timeBuf).update(timeBuf).digest();
  const cipher = crypto.createCipheriv("aes-128-cfb", cmdKey, cmdIV);
  const encryptedHeader = Buffer.concat([cipher.update(fullInner), cipher.final()]);
  const header = Buffer.concat([authInfo, encryptedHeader]);
  const dataKey = crypto.createHash("md5").update(requestKey).digest();
  const dataIV = crypto.createHash("md5").update(requestIV).digest();
  return { header, dataKey, dataIV };
}

function createVmessSocket(proxy: ProxyInfo, targetHost: string, targetPort: number, timeoutMs: number, isUdp = false): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("VMess connection timeout")), timeoutMs);
    const cleanup = () => { if (timer) { clearTimeout(timer); timer = null; } };
    const isTls = proxy.security === "tls";
    const transport = proxy.transport || "tcp";
    const secType = proxy.vmessSecurity || "auto";
    const actualSec = secType === "auto" ? "aes-128-gcm" : secType;
    const { header: vmessHeader, dataKey, dataIV } = buildVmessRequestHeader(proxy.uuid || "", targetHost, targetPort, actualSec, isUdp);

    let rawSocket: net.Socket = isTls
      ? tls.connect({ host: proxy.host, port: proxy.port, servername: proxy.sni || proxy.host, rejectUnauthorized: false })
      : net.createConnection({ host: proxy.host, port: proxy.port });

    rawSocket.on("error", (err) => { cleanup(); reject(err); });

    const setupStream = () => {
      if (transport === "ws") {
        const wsKey = crypto.randomBytes(16).toString("base64");
        const wsReq =
          `GET ${proxy.wsPath || "/"} HTTP/1.1\r\n` +
          `Host: ${proxy.wsHost || proxy.host}\r\n` +
          `Upgrade: websocket\r\n` +
          `Connection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${wsKey}\r\n` +
          `Sec-WebSocket-Version: 13\r\n\r\n`;
        rawSocket.write(wsReq);
        let httpBuf = "";
        let httpDone = false;
        const onWsSetup = (chunk: Buffer) => {
          if (!httpDone) {
            httpBuf += chunk.toString("binary");
            const end = httpBuf.indexOf("\r\n\r\n");
            if (end !== -1) {
              httpDone = true;
              rawSocket.removeListener("data", onWsSetup);
              finishVmessSetup(rawSocket, vmessHeader, dataKey, dataIV, actualSec, true, cleanup, resolve);
            }
          }
        };
        rawSocket.on("data", onWsSetup);
      } else {
        finishVmessSetup(rawSocket, vmessHeader, dataKey, dataIV, actualSec, false, cleanup, resolve);
      }
    };

    if (isTls) (rawSocket as tls.TLSSocket).on("secureConnect", setupStream);
    else rawSocket.on("connect", setupStream);
  });
}

function finishVmessSetup(
  rawSocket: net.Socket,
  vmessHeader: Buffer,
  dataKey: Buffer,
  dataIV: Buffer,
  secType: string,
  isWs: boolean,
  cleanup: () => void,
  resolve: (sock: net.Socket) => void
): void {
  const sendRaw = (data: Buffer) => {
    if (isWs) {
      const mKey = crypto.randomBytes(4);
      const masked = Buffer.alloc(data.length);
      for (let i = 0; i < data.length; i++) masked[i] = data[i] ^ mKey[i % 4];
      let wsFrame: Buffer;
      if (data.length <= 125) {
        wsFrame = Buffer.concat([Buffer.from([0x82, 0x80 | data.length]), mKey, masked]);
      } else if (data.length <= 65535) {
        const lb = Buffer.alloc(2);
        lb.writeUInt16BE(data.length, 0);
        wsFrame = Buffer.concat([Buffer.from([0x82, 0x80 | 126]), lb, mKey, masked]);
      } else {
        const lb = Buffer.alloc(8);
        lb.writeBigUInt64BE(BigInt(data.length), 0);
        wsFrame = Buffer.concat([Buffer.from([0x82, 0x80 | 127]), lb, mKey, masked]);
      }
      rawSocket.write(wsFrame);
    } else {
      rawSocket.write(data);
    }
  };

  let sendNonce = 0;
  const encryptChunk = (chunk: Buffer): Buffer => {
    if (secType === "none") {
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(chunk.length, 0);
      return Buffer.concat([lenBuf, chunk]);
    }
    const nonceBuf = Buffer.alloc(12, 0);
    nonceBuf.writeUInt16BE(sendNonce++, 0);
    nonceBuf[0] ^= dataIV[0];
    nonceBuf[1] ^= dataIV[1];
    const cipher = crypto.createCipheriv("aes-128-gcm", dataKey, nonceBuf, { authTagLength: 16 } as any) as crypto.CipherGCM;
    const enc = Buffer.concat([cipher.update(chunk), cipher.final()]);
    const tag = cipher.getAuthTag();
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(enc.length + tag.length, 0);
    return Buffer.concat([lenBuf, enc, tag]);
  };

  sendRaw(vmessHeader);
  const clientSocket = new net.Socket();
  clientSocket.write = function (data: any, cb?: any): boolean {
    const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
    sendRaw(encryptChunk(b));
    if (typeof cb === "function") cb();
    return true;
  };
  clientSocket.destroy = function (e?: Error) { rawSocket.destroy(e); return this; };

  let respHeaderRead = false;
  const processVmessPayload = (data: Buffer) => {
    if (!respHeaderRead) {
      if (data.length >= 4) {
        respHeaderRead = true;
        const cmdLen = data[3];
        const rest = data.subarray(4 + cmdLen);
        if (rest.length > 0) clientSocket.emit("data", rest);
      }
    } else {
      clientSocket.emit("data", data);
    }
  };

  rawSocket.on("data", (data: Buffer) => {
    if (isWs) {
      let pos = 0;
      while (pos < data.length) {
        if (pos + 2 > data.length) break;
        pos++;
        const b1 = data[pos++];
        let pLen = b1 & 0x7f;
        if (pLen === 126) {
          if (pos + 2 > data.length) break;
          pLen = data.readUInt16BE(pos);
          pos += 2;
        } else if (pLen === 127) {
          if (pos + 8 > data.length) break;
          pLen = Number(data.readBigUInt64BE(pos));
          pos += 8;
        }
        if (pos + pLen > data.length) break;
        const payload = data.subarray(pos, pos + pLen);
        pos += pLen;
        if (payload.length > 0) processVmessPayload(payload);
      }
    } else {
      processVmessPayload(data);
    }
  });

  cleanup();
  resolve(clientSocket);
}

function createHttpsConnectSocket(proxy: ProxyInfo, targetHost: string, targetPort: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("HTTPS proxy timeout")), timeoutMs);
    const cleanup = () => { if (timer) { clearTimeout(timer); timer = null; } };
    const tlsSock = tls.connect({
      host: proxy.host,
      port: proxy.port,
      servername: proxy.host,
      rejectUnauthorized: false,
    });
    tlsSock.on("error", (e) => { cleanup(); reject(e); });
    tlsSock.on("secureConnect", () => {
      let authHeader = "";
      if (proxy.username && proxy.password) {
        const creds = Buffer.from(`${proxy.username}:${proxy.password}`).toString("base64");
        authHeader = `Proxy-Authorization: Basic ${creds}\r\n`;
      }
      const req = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${authHeader}Proxy-Connection: Keep-Alive\r\n\r\n`;
      tlsSock.write(req);
    });
    let buffer = "";
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("binary");
      const endOfHeader = buffer.indexOf("\r\n\r\n");
      if (endOfHeader !== -1) {
        tlsSock.removeListener("data", onData);
        cleanup();
        const statusLine = buffer.split("\r\n")[0];
        if (statusLine.includes("200")) {
          const rest = Buffer.from(buffer.substring(endOfHeader + 4), "binary");
          resolve(tlsSock);
          if (rest.length > 0) tlsSock.emit("data", rest);
        } else {
          tlsSock.destroy();
          reject(new Error(`HTTPS CONNECT failed: ${statusLine}`));
        }
      }
    };
    tlsSock.on("data", onData);
  });
}

function createHysteria2Socket(proxy: ProxyInfo, targetHost: string, targetPort: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("Hysteria2 connection timeout")), timeoutMs);
    const cleanup = () => { if (timer) { clearTimeout(timer); timer = null; } };
    const password = proxy.hysteria2Password || "";
    try {
      const h2Session = http2.connect(`https://${proxy.host}:${proxy.port}`, {
        rejectUnauthorized: false,
        servername: proxy.sni || proxy.host,
      });
      h2Session.on("error", () => {
        cleanup();
        h2Session.close();
        createHysteria2TlsFallback(proxy, targetHost, targetPort, timeoutMs).then(resolve).catch(reject);
      });
      h2Session.on("connect", () => {
        const headers: Record<string, string> = {
          ":method": "CONNECT",
          ":authority": `${targetHost}:${targetPort}`,
        };
        if (password) {
          headers["proxy-authorization"] = `Basic ${Buffer.from(`hysteria:${password}`).toString("base64")}`;
        }
        const stream = h2Session.request(headers);
        stream.on("response", (responseHeaders) => {
          const status = responseHeaders[":status"];
          if (status === 200) {
            cleanup();
            const clientSocket = new net.Socket();
            clientSocket.write = function (data: any, cb?: any): boolean {
              const b = Buffer.isBuffer(data) ? data : Buffer.from(data);
              return stream.write(b, cb);
            };
            clientSocket.destroy = function () {
              stream.close();
              h2Session.close();
              return this;
            };
            stream.on("data", (chunk: Buffer) => clientSocket.emit("data", chunk));
            stream.on("end", () => clientSocket.emit("close", false));
            stream.on("error", (e) => clientSocket.emit("error", e));
            resolve(clientSocket);
          } else {
            cleanup();
            stream.close();
            h2Session.close();
            reject(new Error(`Hysteria2 HTTP/2 CONNECT failed with status: ${status}`));
          }
        });
        stream.on("error", (err) => { cleanup(); h2Session.close(); reject(err); });
      });
    } catch {
      cleanup();
      createHysteria2TlsFallback(proxy, targetHost, targetPort, timeoutMs).then(resolve).catch(reject);
    }
  });
}

function createHysteria2TlsFallback(proxy: ProxyInfo, targetHost: string, targetPort: number, timeoutMs: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("Hysteria2 TLS fallback timeout")), timeoutMs);
    const cleanup = () => { if (timer) { clearTimeout(timer); timer = null; } };
    const password = proxy.hysteria2Password || "";
    const tlsSock = tls.connect({
      host: proxy.host,
      port: proxy.port,
      servername: proxy.sni || proxy.host,
      rejectUnauthorized: false,
      ALPNProtocols: ["h2", "http/1.1"],
    });
    tlsSock.on("error", (e) => { cleanup(); reject(e); });
    tlsSock.on("secureConnect", () => {
      let authHeader = "";
      if (password) {
        authHeader = `Proxy-Authorization: Basic ${Buffer.from(`hysteria:${password}`).toString("base64")}\r\n`;
      }
      const req = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${authHeader}Connection: Keep-Alive\r\n\r\n`;
      tlsSock.write(req);
    });
    let buffer = "";
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("binary");
      const endOfHeader = buffer.indexOf("\r\n\r\n");
      if (endOfHeader !== -1) {
        tlsSock.removeListener("data", onData);
        cleanup();
        const statusLine = buffer.split("\r\n")[0];
        if (statusLine.includes("200")) {
          const rest = Buffer.from(buffer.substring(endOfHeader + 4), "binary");
          resolve(tlsSock);
          if (rest.length > 0) tlsSock.emit("data", rest);
        } else {
          tlsSock.destroy();
          reject(new Error(`Hysteria2 TLS fallback CONNECT failed: ${statusLine}`));
        }
      }
    };
    tlsSock.on("data", onData);
  });
}

export async function connectViaProxy(
  proxy: ProxyInfo,
  targetHost: string,
  targetPort: number,
  timeoutMs = 6000
): Promise<net.Socket> {
  switch (proxy.type) {
    case "socks5":
    case "socks4": {
      const type = proxy.type === "socks4" ? 4 : 5;
      const client = await SocksClient.createConnection({
        proxy: {
          host: proxy.host,
          port: proxy.port,
          type: type as any,
          userId: proxy.username,
          password: proxy.password,
        },
        command: "connect",
        destination: { host: targetHost, port: targetPort },
        timeout: timeoutMs,
      });
      return client.socket;
    }
    case "http":
      return createHttpConnectSocket(proxy, targetHost, targetPort, timeoutMs);
    case "https":
      return createHttpsConnectSocket(proxy, targetHost, targetPort, timeoutMs);
    case "shadowsocks":
      return new Promise<net.Socket>((resolve, reject) => {
        let timer: NodeJS.Timeout | null = setTimeout(() => reject(new Error("Shadowsocks connection timeout")), timeoutMs);
        const rawSocket = net.createConnection({ host: proxy.host, port: proxy.port }, () => {
          if (timer) { clearTimeout(timer); timer = null; }
          createShadowsocksSocket(rawSocket, proxy, targetHost, targetPort, (sock) => resolve(sock), (err) => reject(err));
        });
        rawSocket.on("error", (e) => { if (timer) clearTimeout(timer); reject(e); });
      });
    case "vless":
      return createVlessSocket(proxy, targetHost, targetPort, timeoutMs, false);
    case "trojan":
      return createTrojanSocket(proxy, targetHost, targetPort, timeoutMs);
    case "vmess":
      return createVmessSocket(proxy, targetHost, targetPort, timeoutMs, false);
    case "hysteria2":
      return createHysteria2Socket(proxy, targetHost, targetPort, timeoutMs);
    case "direct":
    default:
      return new Promise<net.Socket>((resolve, reject) => {
        const sock = net.createConnection({ host: targetHost, port: targetPort }, () => resolve(sock));
        sock.on("error", reject);
      });
  }
}

export async function createSocks5UdpRelay(proxy: ProxyInfo, timeoutMs = 8000): Promise<UdpRelay> {
  if (proxy.type !== "socks5" && proxy.type !== "socks4") {
    throw new Error("only socks5/socks4");
  }
  const control = await SocksClient.createConnection({
    proxy: {
      host: proxy.host,
      port: proxy.port,
      type: proxy.type === "socks4" ? 4 : 5,
      userId: proxy.username,
      password: proxy.password,
    },
    command: "associate",
    destination: { host: "0.0.0.0", port: 0 },
    timeout: timeoutMs,
  });
  const controlSocket = control.socket;
  const relayHost = (control as any).remoteHost || proxy.host;
  const relayPort = (control as any).remotePort;
  if (!relayPort) {
    controlSocket.destroy();
    throw new Error("no relay port");
  }
  const udp = dgram.createSocket("udp4");
  const relay: UdpRelay = {
    onMessage: null,
    onError: null,
    send(data: Buffer, targetHost: string, targetPort: number) {
      let addrBuf: Buffer;
      let atyp: number;
      if (net.isIPv4(targetHost)) {
        atyp = 0x01;
        addrBuf = Buffer.from(targetHost.split(".").map(Number));
      } else {
        atyp = 0x03;
        const hostBytes = Buffer.from(targetHost, "utf8");
        addrBuf = Buffer.concat([Buffer.from([hostBytes.length]), hostBytes]);
      }
      const portBuf = Buffer.alloc(2);
      portBuf.writeUInt16BE(targetPort, 0);
      const header = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, atyp]), addrBuf, portBuf]);
      udp.send(Buffer.concat([header, data]), relayPort, relayHost);
    },
    close() {
      try { udp.close(); } catch {}
      try { controlSocket.destroy(); } catch {}
    },
  };
  udp.on("message", (msg) => {
    if (msg.length < 10) return;
    let offset = 3;
    const atyp = msg[offset++];
    let host = "";
    let port = 0;
    if (atyp === 0x01) {
      host = `${msg[offset]}.${msg[offset + 1]}.${msg[offset + 2]}.${msg[offset + 3]}`;
      offset += 4;
    } else if (atyp === 0x03) {
      const len = msg[offset++];
      host = msg.subarray(offset, offset + len).toString("utf8");
      offset += len;
    } else if (atyp === 0x04) {
      offset += 16;
      host = "ipv6";
    } else return;
    port = msg.readUInt16BE(offset);
    offset += 2;
    const payload = msg.subarray(offset);
    if (relay.onMessage) relay.onMessage(payload, host, port);
  });
  udp.on("error", (err) => { if (relay.onError) relay.onError(err); });
  controlSocket.on("error", (err) => { if (relay.onError) relay.onError(err); });
  controlSocket.on("close", () => { try { udp.close(); } catch {} });
  return relay;
}

export function createShadowsocksUdpRelay(proxy: ProxyInfo): UdpRelay {
  if (proxy.type !== "shadowsocks") throw new Error("only shadowsocks");
  const method = (proxy.cipherMethod || "aes-256-gcm").toLowerCase();
  const password = proxy.password || "";
  const { keySize, saltSize, isAEAD } = getShadowsocksKeySize(method);
  if (!isAEAD) throw new Error("only AEAD");
  const masterKey = kdf(password, keySize);
  const cipherName = method.startsWith("chacha20") ? "chacha20-poly1305" : method;
  const udp = dgram.createSocket("udp4");
  const relay: UdpRelay = {
    onMessage: null,
    onError: null,
    send(data: Buffer, targetHost: string, targetPort: number) {
      let addrBuf: Buffer;
      if (net.isIPv4(targetHost)) {
        const ip = targetHost.split(".").map(Number);
        addrBuf = Buffer.alloc(1 + 4 + 2);
        addrBuf[0] = 0x01;
        Buffer.from(ip).copy(addrBuf, 1);
        addrBuf.writeUInt16BE(targetPort, 5);
      } else {
        const hostBytes = Buffer.from(targetHost, "utf8");
        addrBuf = Buffer.alloc(1 + 1 + hostBytes.length + 2);
        addrBuf[0] = 0x03;
        addrBuf[1] = hostBytes.length;
        hostBytes.copy(addrBuf, 2);
        addrBuf.writeUInt16BE(targetPort, 2 + hostBytes.length);
      }
      const payload = Buffer.concat([addrBuf, data]);
      const salt = crypto.randomBytes(saltSize);
      const subkey = hkdfSubkey(masterKey, salt, keySize);
      const nonce = Buffer.alloc(12, 0);
      const cipher = crypto.createCipheriv(cipherName, subkey, nonce, { authTagLength: 16 } as any) as crypto.CipherGCM;
      const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
      const tag = cipher.getAuthTag();
      udp.send(Buffer.concat([salt, encrypted, tag]), proxy.port, proxy.host);
    },
    close() { try { udp.close(); } catch {} },
  };
  udp.on("message", (msg) => {
    if (msg.length < saltSize + 16) return;
    const salt = msg.subarray(0, saltSize);
    const tag = msg.subarray(msg.length - 16);
    const encrypted = msg.subarray(saltSize, msg.length - 16);
    try {
      const subkey = hkdfSubkey(masterKey, salt, keySize);
      const nonce = Buffer.alloc(12, 0);
      const decipher = crypto.createDecipheriv(cipherName, subkey, nonce, { authTagLength: 16 } as any) as crypto.DecipherGCM;
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      let offset = 0;
      const atyp = decrypted[offset++];
      let host = "";
      let port = 0;
      if (atyp === 0x01) {
        host = `${decrypted[offset]}.${decrypted[offset + 1]}.${decrypted[offset + 2]}.${decrypted[offset + 3]}`;
        offset += 4;
      } else if (atyp === 0x03) {
        const len = decrypted[offset++];
        host = decrypted.subarray(offset, offset + len).toString("utf8");
        offset += len;
      } else return;
      port = decrypted.readUInt16BE(offset);
      offset += 2;
      const payload = decrypted.subarray(offset);
      if (relay.onMessage) relay.onMessage(payload, host, port);
    } catch (e: any) {
      if (relay.onError) relay.onError(e);
    }
  });
  udp.on("error", (err) => { if (relay.onError) relay.onError(err); });
  return relay;
}

export async function createVlessUdpRelay(proxy: ProxyInfo, timeoutMs = 8000): Promise<UdpRelay> {
  if (proxy.type !== "vless") throw new Error("only vless");
  const socket = await createVlessSocket(proxy, "0.0.0.0", 0, timeoutMs, true);
  const relay: UdpRelay = {
    onMessage: null,
    onError: null,
    send(data: Buffer, targetHost: string, targetPort: number) {
      let addrBuf: Buffer;
      let atyp: number;
      if (net.isIPv4(targetHost)) {
        atyp = 0x01;
        addrBuf = Buffer.from(targetHost.split(".").map(Number));
      } else {
        atyp = 0x02;
        const hostBytes = Buffer.from(targetHost, "utf8");
        addrBuf = Buffer.concat([Buffer.from([hostBytes.length]), hostBytes]);
      }
      const portBuf = Buffer.alloc(2);
      portBuf.writeUInt16BE(targetPort, 0);
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(data.length, 0);
      const packet = Buffer.concat([Buffer.from([atyp]), addrBuf, portBuf, lenBuf, data]);
      socket.write(packet);
    },
    close() { try { socket.destroy(); } catch {} },
  };
  socket.on("data", (chunk: Buffer) => {
    let offset = 0;
    while (offset + 1 < chunk.length) {
      const atyp = chunk[offset++];
      let host = "";
      let port = 0;
      if (atyp === 0x01) {
        if (offset + 6 > chunk.length) break;
        host = `${chunk[offset]}.${chunk[offset + 1]}.${chunk[offset + 2]}.${chunk[offset + 3]}`;
        offset += 4;
      } else if (atyp === 0x02) {
        const len = chunk[offset++];
        if (offset + len + 2 > chunk.length) break;
        host = chunk.subarray(offset, offset + len).toString("utf8");
        offset += len;
      } else break;
      port = chunk.readUInt16BE(offset);
      offset += 2;
      if (offset + 2 > chunk.length) break;
      const dataLen = chunk.readUInt16BE(offset);
      offset += 2;
      if (offset + dataLen > chunk.length) break;
      const payload = chunk.subarray(offset, offset + dataLen);
      offset += dataLen;
      if (relay.onMessage) relay.onMessage(payload, host, port);
    }
  });
  socket.on("error", (err) => { if (relay.onError) relay.onError(err); });
  return relay;
}

export async function createVmessUdpRelay(proxy: ProxyInfo, timeoutMs = 8000): Promise<UdpRelay> {
  if (proxy.type !== "vmess") throw new Error("only vmess");
  const socket = await createVmessSocket(proxy, "0.0.0.0", 0, timeoutMs, true);
  const relay: UdpRelay = {
    onMessage: null,
    onError: null,
    send(data: Buffer, targetHost: string, targetPort: number) {
      let addrBuf: Buffer;
      let atyp: number;
      if (net.isIPv4(targetHost)) {
        atyp = 0x01;
        addrBuf = Buffer.from(targetHost.split(".").map(Number));
      } else {
        atyp = 0x02;
        const hostBytes = Buffer.from(targetHost, "utf8");
        addrBuf = Buffer.concat([Buffer.from([hostBytes.length]), hostBytes]);
      }
      const portBuf = Buffer.alloc(2);
      portBuf.writeUInt16BE(targetPort, 0);
      const packet = Buffer.concat([Buffer.from([atyp]), addrBuf, portBuf, data]);
      socket.write(packet);
    },
    close() { try { socket.destroy(); } catch {} },
  };
  socket.on("data", (chunk: Buffer) => {
    if (relay.onMessage) relay.onMessage(chunk, "", 0);
  });
  socket.on("error", (err) => { if (relay.onError) relay.onError(err); });
  return relay;
}

export async function createUdpRelay(proxy: ProxyInfo, timeoutMs = 8000): Promise<UdpRelay> {
  switch (proxy.type) {
    case "socks5":
    case "socks4":
      return createSocks5UdpRelay(proxy, timeoutMs);
    case "shadowsocks":
      return createShadowsocksUdpRelay(proxy);
    case "vless":
      return createVlessUdpRelay(proxy, timeoutMs);
    case "vmess":
      return createVmessUdpRelay(proxy, timeoutMs);
    default:
      throw new Error(`UDP not supported for ${proxy.type}`);
  }
}