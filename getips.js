/**
 * Fetch IP addresses from MS Activity page.
 * Uses Advanced Regex, Deep HTML Unescaping, and API POST fallback.
 * @param {Object} axios - Axios instance.
 * @returns {Promise<Array<string>|null>} - Unique IPs or null.
 */
module.exports = async (axios) => {
    try {
        const now = new Date();
        
        // Format time for payload
        const formatTime = (date) => {
            return `${date.getFullYear()}/${String(date.getMonth() + 1).padStart(2, '0')}/${String(date.getDate()).padStart(2, '0')} ` +
                   `${String(date.getHours()).padStart(2, '0')}:${String(date.getMinutes()).padStart(2, '0')}:${String(date.getSeconds()).padStart(2, '0')}`;
        };
        const utcNow = formatTime(now);

        // Sync User-Agent to avoid detection
        const userAgent = (axios.defaults?.headers?.common?.['User-Agent']) 
                          || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36';

        // 1. Fetch MS Activity page
        const initialResponse = await axios.get('https://account.live.com/Activity', {
            params: { 'mkt': 'en-US', 'refd': 'account.microsoft.com', 'refp': 'security' },
            headers: {
                'User-Agent': userAgent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            },
            validateStatus: () => true
        });

        let html = initialResponse.data || "";
        let ipList = [];

        // Check for Security Wall
        if (html.includes('Verify your identity') || html.includes('Sign in to your') || initialResponse.status === 302) {
            console.log('[-] [GET_IPS] Blocked by MS security wall (Require Password/TFA).');
        }

        // 2. Deep Unescape HTML (Unicode & HTML Entities)
        const unescapedHtml = html.replace(/\\u([\dA-Fa-f]{4})/g, (_, grp) => String.fromCharCode(parseInt(grp, 16)))
                                  .replace(/\\"/g, '"')
                                  .replace(/\\\//g, '/')
                                  .replace(/&quot;/g, '"');

        // 3. X-Ray Regex 1: Catch IPs hidden in keys
        const jsonKeyIpRegex = /(?:"ip"|"IPAddress"|"ipAddress"|"IpAddress"|IP Address)\s*[:=]\s*["']?([^"'<&\s]+)["']?/gi;
        let match;
        while ((match = jsonKeyIpRegex.exec(unescapedHtml)) !== null) {
            ipList.push(match[1].trim());
        }

        // 4. X-Ray Regex 2: Catch all raw IPv4 strings
        const ipv4Regex = /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
        const allIps = unescapedHtml.match(ipv4Regex) || [];
        ipList.push(...allIps);

        // 5. Original JSON Activity Fallback (Restored)
        const initialJsonMatch = html.match(/var jsonActivity = '(.+?)';/);
        let initialActivityData = {};
        
        if (initialJsonMatch) {
            try {
                initialActivityData = JSON.parse(
                    initialJsonMatch[1].replace(/\\u([\dA-Fa-f]{4})/g, (_, grp) => String.fromCharCode(parseInt(grp, 16)))
                );

                const collectIPs = (items) => {
                    if (!items) return;
                    items.forEach(item => {
                        if (item.ip) ipList.push(item.ip);
                        if (item.IpAddress) ipList.push(item.IpAddress);
                    });
                };

                collectIPs(initialActivityData.reportItems);
                collectIPs(initialActivityData.unusualReportItems);
            } catch (parseError) {
                console.log('[-] [GET_IPS] JSON parse error.');
            }
        }

        let canary = '';
        const canaryMatch = html.match(/id="canary"\s+name="canary"\s+value="([^"]+)"/i) || html.match(/name="canary"\s+id="canary"\s+value="([^"]+)"/i);
        if (canaryMatch) canary = canaryMatch[1];

        // 6. Original API POST Fallback (Restored)
        try {
            if (initialActivityData.lastActivityTime && canary) {
                const apiResponse = await axios.post(
                    'https://account.live.com/API/AccountActivity',
                    {
                        lastActivityTime: initialActivityData.lastActivityTime,
                        utcNow: utcNow,
                        uiflvr: 1001,
                        uaid: "a7ba5b6d20c24f7289cd20b55c2f5956",
                        scid: 100157,
                        hpgid: 200158
                    },
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            'User-Agent': userAgent,
                            'canary': canary,
                            'Accept': 'application/json',
                            'Origin': 'https://account.live.com',
                            'Referer': 'https://account.live.com/Activity'
                        },
                        validateStatus: () => true
                    }
                );

                if (apiResponse.data && apiResponse.data.reportItems) {
                    apiResponse.data.reportItems.forEach((item) => {
                        if (item.ip) ipList.push(item.ip);
                        if (item.IpAddress) ipList.push(item.IpAddress);
                    });
                }
            }
        } catch (postError) {
            console.log('[-] [GET_IPS] POST fallback failed.');
        }

        // 7. Deduplicate and filter out garbage
        const uniqueIPs = [...new Set(ipList)];
        
        const validIPs = uniqueIPs.filter(ip => {
            const isIPv4 = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip);
            const isIPv6 = ip.includes(':') && ip.length > 10 && ip.length < 40 && /^[a-fA-F0-9:]+$/.test(ip);
            
            // Exclude Local IPs and Chrome Version strings
            const isLocal = ip === '127.0.0.1' || ip === '0.0.0.0' || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.');
            const isVersionString = ip.endsWith('.0.0.0') || ip.startsWith('0.');

            return (isIPv4 || isIPv6) && !isLocal && !isVersionString;
        });
        
        if (validIPs.length === 0) {
            console.log('[-] [GET_IPS] No valid IPs found after filtering.');
            return null;
        }
        
        return validIPs;

    } catch (error) {
        console.error('[-] [GET_IPS] Critical Error:', error.message);
        return null;
    }
};
