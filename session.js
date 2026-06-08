const axios = require('axios');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');
const fs = require('fs');
const path = require('path');

/**
 * Creates an Axios instance with an automated Cookie Jar.
 * Mimics httpx.AsyncClient() behavior to prevent session drops during redirects.
 * Automatically applies proxy settings from config.json if available.
 *
 * @returns {Object} Axios client instance with cookie management
 */
function createSession() {
    const jar = new CookieJar();
    let proxyConfig = false;

    // Load proxy configuration from config.json to avoid IP bans
    try {
        const configPath = path.join(process.cwd(), 'config.json');
        if (fs.existsSync(configPath)) {
            const config = require(configPath);
            if (config.useproxy && config.proxy) {
                const parts = config.proxy.split(':');
                if (parts.length === 4) {
                    proxyConfig = {
                        host: parts[0],
                        port: parseInt(parts[1]),
                        auth: { username: parts[2], password: parts[3] },
                        protocol: 'http'
                    };
                } else if (parts.length === 2) {
                    proxyConfig = {
                        host: parts[0],
                        port: parseInt(parts[1]),
                        protocol: 'http'
                    };
                }
            }
        }
    } catch (error) {
        // Ignore config read errors silently
    }

    // Initialize wrapped Axios client
    const client = wrapper(axios.create({
        jar,
        proxy: proxyConfig,
        validateStatus: () => true, // Prevent Axios from throwing exceptions on HTTP 4xx/5xx
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        }
    }));

    return client;
}

module.exports = createSession;
