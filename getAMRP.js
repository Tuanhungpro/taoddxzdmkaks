const axios = require("axios");
const fs = require("fs");
const path = require("path");

// Fetches the AMRPSSecAuth token required for advanced Microsoft account actions.
// Supports both shared HttpClient injection and standalone execution with proxy fallback.
module.exports = async (param1, param2, param3) => {
    let client = axios;
    let t = param1;
    let amsc = param2;
    let useSharedClient = false;

    // Polymorphic signature support:
    // - (axiosClient, t, amsc) when called with a shared HttpClient wrapper
    // - (t, amsc) when called standalone
    if (param1 && typeof param1 === "object" && (param1.post || param1.axios || param1.get)) {
        client = param1;
        t = param2;
        amsc = param3;
        useSharedClient = true;
    }

    let amrp = null;

    try {
        const stringPayload = `t=${encodeURIComponent(t)}`;

        const requestHeaders = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            "Sec-Ch-Ua": '"Not A(Brand";v="8", "Chromium";v="132"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"'
        };

        let response;

        if (useSharedClient) {
            // Use the shared HttpClient wrapper — it manages cookies automatically via interceptors
            response = await client.post("https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0", stringPayload, {
                headers: requestHeaders,
                maxRedirects: 0,
                validateStatus: (status) => status >= 200 && status < 400
            });
        } else {
            // Standalone mode: manually set only the amsc cookie.
            // Do NOT inject MSPAuth=Disabled or MSPProof=Disabled — these poison the
            // shared HttpClient jar if the response echoes them back via set-cookie,
            // causing account.live.com to reject the session on subsequent requests.
            requestHeaders["Cookie"] = `amsc=${amsc};`;

            // Load proxy from config.json if enabled
            let proxyConfig = false;
            try {
                const configPath = path.join(process.cwd(), "config.json");
                if (fs.existsSync(configPath)) {
                    const config = require(configPath);
                    if (config.useproxy && config.proxy) {
                        const parts = config.proxy.split(":");
                        if (parts.length === 4) {
                            proxyConfig = {
                                host: parts[0],
                                port: parseInt(parts[1]),
                                auth: { username: parts[2], password: parts[3] },
                                protocol: "http"
                            };
                        } else if (parts.length === 2) {
                            proxyConfig = {
                                host: parts[0],
                                port: parseInt(parts[1]),
                                protocol: "http"
                            };
                        }
                    }
                }
            } catch (e) {
                // Ignore config read errors
            }

            const standaloneClient = axios.create({
                proxy: proxyConfig,
                validateStatus: () => true
            });

            response = await standaloneClient.post("https://account.live.com/proofs/Add?apt=2&wa=wsignin1.0", stringPayload, {
                headers: requestHeaders,
                maxRedirects: 0
            });
        }

        // Extract AMRPSSecAuth value from Set-Cookie response headers
        if (response?.headers?.["set-cookie"]) {
            response.headers["set-cookie"].forEach((cookie) => {
                const [name, ...values] = cookie.split("=");
                if (name.trim() === "AMRPSSecAuth") {
                    amrp = values.join("=").split(";")[0];
                }
            });
        }

    } catch (error) {
        console.log(`[AMRP] [FAILED] Fetch AMRP error: ${error.message}`);
    }

    return amrp;
};
