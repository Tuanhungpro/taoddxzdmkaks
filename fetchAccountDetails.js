const HttpClient = require("../process/HttpClient");

module.exports = async (email) => {
    const client = new HttpClient();

    try {
        // Fetch the initial login page to generate dynamic session cookies and tokens
        const loginPage = await client.get("https://login.live.com/login.srf");
        const html = loginPage.data;

        let flowToken = null;

        // Fallback extraction regex patterns for PPFT (flowToken)
        const extractors = [
            () => {
                const match = html.match(/var ServerData = ({.*?});/s);
                if (match) {
                    try {
                        const serverData = JSON.parse(match[1]);
                        return serverData.sFTTag?.match(/value="([^"]*)"/)?.[1];
                    } catch (e) { return null; }
                }
            },
            () => html.match(/name="PPFT"[^>]*value="([^"]*)"/)?.[1],
            () => html.match(/value="([^"]*)"[^>]*name="PPFT"/)?.[1],
            () => html.match(/<input[^>]*name="PPFT"[^>]*value="([^"]*)"[^>]*>/)?.[1],
            () => html.match(/<input[^>]*value="([^"]*)"[^>]*name="PPFT"[^>]*>/)?.[1]
        ];

        for (const extractor of extractors) {
            try {
                const token = extractor();
                if (token && token.length > 10) { 
                    flowToken = token; 
                    break; 
                }
            } catch (e) { continue; }
        }

        if (!flowToken) {
            throw new Error("Failed to extract dynamic flowToken (PPFT) from login page.");
        }

        // Extract the unique uaid cookie from the current session jar
        const uaid = client.getCookie("uaid") || "";

        // Prepare the payload with dynamic tokens and telemetry parameters
        const payload = {
            username: email,
            isOtherIdpSupported: true,
            checkPhones: true,
            isRemoteNGCSupported: true,
            isCookieBannerShown: false,
            isFidoSupported: true,
            country: "US",
            forceotclogin: true,
            isOtcLoginSupported: true,
            isAccessPassSupported: true,
            flowToken: flowToken,
            originalRequest: "",
            uaid: uaid,
            federationFlags: 3,
            isSignup: false,
            otclogindisallowed: false
        };

        // Standardized headers to simulate legitimate internal XMLHttpRequest
        const headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "client-request-id": uaid,
            "Origin": "https://login.live.com",
            "Referer": "https://login.live.com/login.srf",
            "X-Requested-With": "XMLHttpRequest",
            "X-Ms-Apiversion": "2"
        };

        const response = await client.post("https://login.live.com/GetCredentialType.srf", payload, { headers });

        // Ensure the account exists and API returned valid data
        if (response.data && response.data.IfExistsResult === 0) {
            return response.data;
        }
        
        return null;

    } catch (error) {
        console.error('[fetchAccountDetails] Dynamic fetch error:', error.message);
        return null;
    }
};
