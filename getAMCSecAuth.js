/**
 * Fetches the AMCSecAuth (amc) token via the silent sign-in API.
 * Injects live session cookies into the header to ensure authentication context
 * and bypasses Microsoft's cross-domain cookie stripping.
 */

module.exports = async (client, t) => {
    // Support varying parameter signatures (client, t) or just (t)
    let requestClient = client;
    let tokenT = t;

    if (typeof client === 'string') {
        tokenT = client;
        requestClient = require('axios');
    }

    if (!tokenT) {
        return null;
    }

    try {
        const axiosInstance = requestClient.axios || requestClient;
        let cookieStr = "";

        // Extract live cookies to prove authentication state
        const sessionCookies = axiosInstance?.defaults?.headers?.common?.['Cookie'];
        if (sessionCookies) {
            cookieStr = sessionCookies;
        } else if (requestClient.cookies && Array.isArray(requestClient.cookies)) {
            cookieStr = requestClient.cookies.map(c => c.split(';')[0]).join('; ');
        }

        const url = "https://account.microsoft.com/auth/complete-silent-signin?ru=https://account.microsoft.com/?lang=nl-NL&refd=account.live.com&refp=landing&mkt=NL-NL&wa=wsignin1.0";
        const data = `t=${encodeURIComponent(tokenT)}`;

        const headers = {
            "Cookie": cookieStr, 
            "Cache-Control": "max-age=0",
            "Origin": "https://login.live.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Referer": "https://login.live.com/"
        };

        // Execute single POST request, strictly prohibiting redirects to catch Set-Cookie
        const response = await axiosInstance.post(url, data, {
            headers,
            maxRedirects: 0,
            validateStatus: () => true
        });

        // Parse response headers for the AMC token
        const setCookies = response.headers["set-cookie"] || response.headers["Set-Cookie"];
        if (setCookies) {
            const cookiesArray = Array.isArray(setCookies) ? setCookies : [setCookies];
            const amcCookie = cookiesArray.find(c => c.toLowerCase().startsWith("amc="));
            
            if (amcCookie) {
                const amcValue = amcCookie.split(";")[0].split("=")[1];
                return amcValue;
            }
        }

        return null;

    } catch (error) {
        return null;
    }
};
