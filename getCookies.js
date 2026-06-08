const decode = require("./decode");
const axios = require("axios");
const fs = require("fs");
const path = require("path");

/**
 * Fetches fresh cookies (apiCanary, sCanary, and amsc).
 * Automatically reads proxy from config.json to maintain IP consistency and prevent WAF blocks.
 */
module.exports = async () => {
    let attempts = 0;
    let apicanary, canary, amsc;

    // 1. Load proxy configuration from config.json
    let proxyConfig = false;
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
    } catch (e) {
        // Ignore config read errors
    }

    // 2. Initialize Axios client with proxy and WAF-bypass configurations
    const client = axios.create({
        proxy: proxyConfig,
        validateStatus: () => true
    });

    // 3. Fetch cookies with retries
    while (attempts < 3) {
        attempts++;
        try {
            const response = await client.get("https://account.live.com/password/reset", {
                headers: {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
                    "Sec-Ch-Ua": '"Not A(Brand";v="8", "Chromium";v="132"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"'
                }
            });

            const html = response.data || "";

            // Extract apiCanary
            const apiCanaryMatch = html.match(/"apiCanary":"([^"]+)"/);
            if (apiCanaryMatch && apiCanaryMatch[1]) {
                apicanary = decode(apiCanaryMatch[1]);
            }

            // Extract sCanary
            const sCanaryMatch = html.match(/"sCanary":\s*"([^"]+)"/);
            if (sCanaryMatch && sCanaryMatch[1]) {
                canary = decode(sCanaryMatch[1]);
            }

            // Extract amsc
            if (response.headers && response.headers["set-cookie"]) {
                response.headers["set-cookie"].forEach((cookie) => {
                    const [name, ...values] = cookie.split("=");
                    if (name.trim() === "amsc") {
                        amsc = values.join("=").split(";")[0];
                    }
                });
            }

            // Return array if all required parameters are successfully retrieved
            if (apicanary && canary && amsc) {
                return [apicanary, amsc, canary];
            }

        } catch (error) {
            if (attempts >= 3) {
                console.log(`[COOKIES] [FAILED] Fetch error: ${error.message}`);
            }
        }
        
        // Wait 1 second before retrying to prevent rate limiting
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log(`[COOKIES] [FAILED] Could not fetch complete canary and cookies.`);
    return null;
};
