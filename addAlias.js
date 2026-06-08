/**
 * Microsoft Account Alias Creation & Make Primary Flow.
 * ADVANCED ENGINE: Includes dynamic JS Form Auto-Submit bypass to break out of
 * infinite auth loops (fmHF) and a Vault Fallback for missing cookies.
 */

const { URLSearchParams, URL } = require('url');

module.exports = async (client, aliasName, assocCanary, cookiedata, amsc, loginCookie, secEmail, apiCanary, email, password) => {

    // =========================================================================
    // 1. BUILD MASTER COOKIE (3-Source Priority)
    // =========================================================================
    const buildMasterCookie = () => {
        let cookieMap = new Map();

        const injectCleanCookie = (cookieStr) => {
            if (!cookieStr) return;
            cookieStr.split(';').forEach(c => {
                let part = c.trim();
                let pLower = part.toLowerCase();
                if (pLower.startsWith('path=') || pLower.startsWith('domain=') || pLower.startsWith('expires=') || pLower === 'secure' || pLower === 'httponly') return;
                let idx = part.indexOf('=');
                if (idx > 0) cookieMap.set(part.substring(0, idx).trim(), part.substring(idx + 1).trim());
            });
        };

        // Source 1: Base login token
        injectCleanCookie(loginCookie);

        // Source 2: Elevated tokens
        if (cookiedata?.cookies?.amrp) cookieMap.set('AMRPSSecAuth', cookiedata.cookies.amrp);
        if (cookiedata?.cookies?.amc)  cookieMap.set('amc',          cookiedata.cookies.amc);
        if (cookiedata?.cookies?.jwt)  cookieMap.set('AMCSecAuthJWT', cookiedata.cookies.jwt);
        if (amsc)                      cookieMap.set('amsc',          amsc);

        // Source 3: Live session cookies (Highest priority)
        const axiosInstance = client.axios || client;
        const sessionCookies = axiosInstance?.defaults?.headers?.common?.['Cookie'];
        
        if (sessionCookies) {
            injectCleanCookie(sessionCookies);
        } else if (client.cookies && Array.isArray(client.cookies)) {
            client.cookies.forEach(fullCookie => {
                let mainPart = fullCookie.split(';')[0];
                injectCleanCookie(mainPart);
            });
        }

        return Array.from(cookieMap.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
    };

    let sessionCookieStr = buildMasterCookie();
    const isAxios = typeof client.post === 'function' && client.post.length >= 3;

    // =========================================================================
    // 2. REQUEST ENGINE (Manual Redirect & Cookie Merger)
    // =========================================================================
    async function request(method, url, { data = null, headers = {}, followRedirects = false } = {}) {
        let currentUrl    = url;
        let currentMethod = method.toUpperCase();
        let currentData   = data;
        let res;
        const maxHops = followRedirects ? 8 : 0;

        for (let i = 0; i <= maxHops; i++) {
            const finalHeaders = {
                'Cookie':     sessionCookieStr,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
                ...headers
            };

            const reqOptions = {
                headers:         finalHeaders,
                maxRedirects:    0,
                disableRedirect: true,
                validateStatus:  () => true
            };

            try {
                if (currentMethod === 'GET') {
                    res = await client.get(currentUrl, reqOptions);
                } else {
                    if (isAxios) {
                        res = await client.post(currentUrl, currentData, reqOptions);
                    } else {
                        reqOptions.body = currentData;
                        res = await client.post(currentUrl, reqOptions);
                    }
                }

                res.text = typeof res.data === 'string' ? res.data
                         : res.body ? (typeof res.body === 'string' ? res.body : JSON.stringify(res.body))
                         : JSON.stringify(res.data || '');

                const resHeaders = res.headers || {};
                const setCookies = resHeaders['set-cookie'] || resHeaders['Set-Cookie'];
                
                if (setCookies) {
                    let cookieMap = new Map();
                    sessionCookieStr.split(';').forEach(c => {
                        let idx = c.indexOf('=');
                        if (idx > 0) cookieMap.set(c.substring(0, idx).trim(), c.substring(idx + 1).trim());
                    });
                    const newCookies = Array.isArray(setCookies) ? setCookies : [setCookies];
                    newCookies.forEach(fullCookie => {
                        const mainPart = fullCookie.split(';')[0].trim();
                        let idx = mainPart.indexOf('=');
                        if (idx > 0) cookieMap.set(mainPart.substring(0, idx).trim(), mainPart.substring(idx + 1).trim());
                    });
                    sessionCookieStr = Array.from(cookieMap.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
                }

                const status   = parseInt(res.status || res.statusCode || 200);
                const location = resHeaders.location || resHeaders.Location;

                if (status >= 300 && status < 400 && location && i < maxHops) {
                    currentUrl    = location.startsWith('http') ? location : new URL(location, currentUrl).href;
                    currentMethod = 'GET';
                    currentData   = null;
                    delete headers['Content-Type'];
                    continue;
                }
                break;
            } catch (err) {
                res = err.response || err;
                if (res && !res.text) {
                    const raw = res.data || res.body || '';
                    res.text = typeof raw === 'string' ? raw : JSON.stringify(raw);
                }
                break;
            }
        }
        return res;
    }

    // =========================================================================
    // 3. HELPER FUNCTIONS (Extractors & Bounce Handlers)
    // =========================================================================
    const extractCanary = (text) => {
        if (!text) return null;
        const match = text.match(/name=["']?canary["']?\s+value=["']([^"']+)["']/i)
                   || text.match(/value=["']([^"']+)["'][^>]*name=["']?canary["']?/i)
                   || text.match(/"canary"\s*:\s*"([^"]+)"/i)
                   || text.match(/'canary'\s*:\s*'([^']+)'/i);
        return match ? match[1] : null;
    };

    const extractFormInputs = (html) => {
        const payload = new URLSearchParams();
        const r1 = /<input[^>]+name=["']([^"']+)["'][^>]+value=["']([^"']*)["']/gi;
        const r2 = /<input[^>]+value=["']([^"']*)["'][^>]+name=["']([^"']+)["']/gi;
        let m;
        while ((m = r1.exec(html)) !== null) payload.append(m[1], m[2]);
        while ((m = r2.exec(html)) !== null) if (!payload.has(m[2])) payload.append(m[2], m[1]);
        return payload;
    };

    try {
        let canary = null;

        // =====================================================================
        // STEP 1: Front Door Initiation
        // =====================================================================
        const res1 = await request('GET', 'https://account.live.com/AddAssocId', {
            headers: { 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' },
            followRedirects: true
        });

        canary = extractCanary(res1.text);

        if (!canary) {
            const codeMatch  = res1.text.match(/name=["']?code["']?[^>]*value=["']([^"']+)["']/i) || res1.text.match(/value=["']([^"']+)["'][^>]*name=["']?code["']?/i);
            const stateMatch = res1.text.match(/name=["']?state["']?[^>]*value=["']([^"']+)["']/i) || res1.text.match(/value=["']([^"']+)["'][^>]*name=["']?state["']?/i);

            if (codeMatch && stateMatch) {
                const oauthCode  = decodeURIComponent(codeMatch[1]);
                const oauthState = decodeURIComponent(stateMatch[1]);

                await request('POST', 'https://account.live.com/auth/redirect', {
                    data: new URLSearchParams({ code: oauthCode, state: oauthState }).toString(),
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    followRedirects: false
                });

                let res3 = await request('GET', 'https://account.live.com/AddAssocId', { followRedirects: true });
                canary = extractCanary(res3.text);

                // Auto-Submit JS Bounce Bypass (fmHF)
                if (!canary && res3.text.includes('id="fmHF"')) {
                    const actionMatch = res3.text.match(/action=["']([^"']+)["']/i);
                    if (actionMatch) {
                        const bouncePayload = extractFormInputs(res3.text);
                        res3 = await request('POST', actionMatch[1].replace(/&amp;/g, '&'), {
                            data: bouncePayload.toString(),
                            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                            followRedirects: true
                        });
                        canary = extractCanary(res3.text);
                    }
                }
            }
        }

        // =====================================================================
        // STEP 2: Vault Fallback (/names/manage)
        // =====================================================================
        if (!canary) {
            let vaultRes = await request('GET', 'https://account.live.com/names/manage', { followRedirects: true });
            
            if (vaultRes.text.includes('id="fmHF"')) {
                const actionMatch = vaultRes.text.match(/action=["']([^"']+)["']/i);
                if (actionMatch) {
                    const bouncePayload = extractFormInputs(vaultRes.text);
                    vaultRes = await request('POST', actionMatch[1].replace(/&amp;/g, '&'), {
                        data: bouncePayload.toString(),
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        followRedirects: true
                    });
                }
            }
            canary = extractCanary(vaultRes.text);
        }

        if (!canary) return false;

        // =====================================================================
        // STEP 3: Submit AddAlias Request
        // =====================================================================
        const addRes = await request('POST', 'https://account.live.com/AddAssocId?ru=&cru=&fl=', {
            data: new URLSearchParams({
                canary:            canary,
                PostOption:        'LIVE',
                SingleDomain:      'outlook.com',
                UpSell:            '',
                AddAssocIdOptions: 'LIVE',
                AssociatedIdLive:  aliasName
            }).toString(),
            headers: {
                'Content-Type':   'application/x-www-form-urlencoded',
                'Origin':         'https://account.live.com',
                'Referer':        'https://account.live.com/AddAssocId',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-User': '?1',
                'Sec-Fetch-Dest': 'document'
            },
            followRedirects: true
        });

        if (addRes.text && (addRes.text.includes('limit how frequently') || addRes.text.includes('sErrTxt'))) {
            return false;
        }

        await new Promise(resolve => setTimeout(resolve, 2000));

        // =====================================================================
        // STEP 4: Verify Alias Existence
        // =====================================================================
        const verifyRes = await request('GET', 'https://account.live.com/names/manage', { followRedirects: true });

        if (verifyRes.text && !verifyRes.text.includes(`${aliasName}@outlook.com`)) {
            return false;
        }

        // =====================================================================
        // STEP 5: Make Primary
        // =====================================================================
        const priRes = await request('POST', 'https://account.live.com/API/MakePrimary', {
            data: JSON.stringify({
                aliasName:        `${aliasName}@outlook.com`,
                emailChecked:     true,
                removeOldPrimary: true,
                uiflvr:           1001,
                scid:             100141,
                hpgid:            200176
            }),
            headers: {
                'Content-Type':     'application/json; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest',
                'Accept':           'application/json',
                'canary':           apiCanary,
                'Referer':          'https://account.live.com/AddAssocId'
            },
            followRedirects: false
        });

        const status = parseInt(priRes.status || priRes.statusCode || 500);
        return status >= 200 && status < 400;

    } catch (error) {
        return false;
    }
};
