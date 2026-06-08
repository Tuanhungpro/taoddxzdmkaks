const getLiveData = require("./getLiveData");
const axios = require("axios");
const axiosRetry = require("axios-retry").default;
const https = require("https");
const getCredentials = require("../info/getCredentials");
const { getEmailDescription } = require("../utils/getEmailDescription");
const sendott = require('./sendott');

// Configure axios-retry for network errors
axiosRetry(axios, { 
    retries: 3, 
    retryDelay: axiosRetry.exponentialDelay,
    retryCondition: (error) => {
        return axiosRetry.isNetworkOrIdempotentRequestError(error) || error.code === 'ECONNRESET';
    }
});

// Reusable HTTPS agent to prevent socket hang up
const httpsAgent = new https.Agent({ keepAlive: true });

module.exports = async function login(obj, creds) {
    let host = null;
    let passwordhost = null;
    let mspok = null;
    let oparams = null;
    let nopassword = false;

    let data = await getLiveData();

    if (!obj?.email) {
        console.log("Missing email.");
        return null;
    }

    if (!data) {
        console.log("Failed to get live data.");
        return null;
    }

    if (!creds) {
        creds = await getCredentials(obj.email);
    }

    if (!creds) {
        console.log(`Failed to get credentials for ${obj.email}`);
        return null;
    }

    if (creds?.Credentials?.HasPassword === 0) {
        nopassword = true;
    }
    console.log(`No password: ${nopassword}`);

    // Parse cookies from live data
    const cookies = data.cookies.split(";").reduce((acc, cookie) => {
        const [name, ...valueParts] = cookie.trim().split("=");
        acc[name] = valueParts.join("=");
        return acc;
    }, {});

    const uaid = cookies["uaid"] || "";
    const mspRequ = cookies["MSPRequ"] || "";
    const mscc = cookies["MSCC"] || "";

    // Safely extract server data from HTML
    function extractServerData(html) {
        try {
            const match = html.match(/var ServerData = ({.*?});/s);
            if (!match) return null;
            return JSON.parse(match[1]);
        } catch (err) {
            return null;
        }
    }

    // Common headers for requests
    const commonHeaders = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": data.cookies,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Connection": "keep-alive"
    };

    try {
        let loginData = null;

        // Flow 1: Login with code
        if (obj.email && obj.id && obj.code) {
            if (nopassword) {
                loginData = await axios({
                    method: "POST",
                    url: "https://login.live.com/ppsecure/post.srf",
                    headers: commonHeaders,
                    httpsAgent: httpsAgent,
                    data: `SentProofIDE=${obj.id}&ProofType=1&npotc=${obj.code}&PPFT=${data.ppft}&PPSX=Pass&login=${obj.email}&type=24`,
                });
            } else {
                loginData = await axios({
                    method: "POST",
                    url: "https://login.live.com/ppsecure/post.srf",
                    headers: commonHeaders,
                    httpsAgent: httpsAgent,
                    data: `login=${obj.email}&type=27&SentProofIDE=${obj.id}&otc=${obj.code}&PPFT=${data.ppft}`,
                });
            }
        } 
        
        // Flow 2: Login with SLK
        else if (obj.slk && obj.email) {
            loginData = await axios({
                method: "POST",
                url: "https://login.live.com/ppsecure/post.srf",
                headers: commonHeaders,
                httpsAgent: httpsAgent,
                data: `login=${obj.email}&slk=${obj.slk}&type=21&PPFT=${data.ppft}`,
            });
        } 

        // Flow 3: Login with password + OTP
        else if (obj.otp && obj.email && obj.pw) {
            console.log("[DEBUG] Start Flow 3: Sending Password...");
            
            const loginpassword = await axios({
                method: "POST",
                url: "https://login.live.com/ppsecure/post.srf",
                headers: commonHeaders,
                httpsAgent: httpsAgent,
                data: `ps=2&PPFT=${data.ppft}&PPSX=PassportRN&NewUser=1&login=${obj.email}&loginfmt=${obj.email}&type=11&passwd=${obj.pw}`,
            });

            console.log(`[DEBUG] Password Request Status: ${loginpassword.status}`);

            if (!loginpassword || loginpassword.status < 200 || loginpassword.status >= 400) {
                console.log("[DEBUG] ERROR: Password request failed.");
                return null;
            }

            // Extract ID and PPFT
            const serverData = extractServerData(loginpassword.data);
            let id = serverData?.arrUserProofs?.find(p => p.type === 10)?.data;
            let secondppft = serverData?.sFT || null;

            if (!id) {
                const regexFallback = /(?<="data":")[^"]+(?=","type":10,"display":)/;
                const matchFallback = loginpassword.data.match(regexFallback);
                if (matchFallback) id = matchFallback[0];
            }

            if (!id) {
                console.log("[DEBUG] ERROR: TOTP id not found. Possible checkpoint or invalid password.");
                return "tfa";
            }

            console.log(`[DEBUG] Proof ID found: ${id}. Secondary PPFT present: ${secondppft !== null}`);

            // Merge all existing and incoming cookies to maintain session state
            let mergedCookies = { ...cookies };
            if (loginpassword.headers["set-cookie"]) {
                loginpassword.headers["set-cookie"].forEach(cookie => {
                    const [name, ...values] = cookie.split("=");
                    const value = values.join("=").split(";").shift();
                    mergedCookies[name] = value;
                    if (name === "__Host-MSAAUTH") passwordhost = value;
                    if (name === "MSPOK") mspok = value;
                    if (name === "OParams") oparams = value;
                });
            }

            console.log(`[DEBUG] Extracted Cookies -> passwordhost: ${!!passwordhost}, MSPOK: ${!!mspok}, OParams: ${!!oparams}`);

            if (!passwordhost) {
                console.log("[DEBUG] WARNING: MS did not return __Host-MSAAUTH after password input.");
            }

            // Format the full cookie string
            const cookieString = Object.entries(mergedCookies)
                .map(([k, v]) => `${k}=${v}`)
                .join("; ");

            const otpHeaders = {
                ...commonHeaders,
                "Cookie": cookieString
            };

            console.log("[DEBUG] Sending OTP...");
            
            loginData = await axios({
                method: "POST",
                url: "https://login.live.com/ppsecure/post.srf",
                headers: otpHeaders,
                httpsAgent: httpsAgent,
                data: `otc=${obj.otp}&AddTD=true&SentProofIDE=${encodeURIComponent(id)}&PPFT=${encodeURIComponent(secondppft)}&type=19&login=${encodeURIComponent(obj.email)}`,
            });
            
            console.log(`[DEBUG] OTP Request Status: ${loginData.status}`);

            // Check if final authentication token is present
            let foundHost = false;
            if (loginData?.headers?.["set-cookie"]) {
                loginData.headers["set-cookie"].forEach(cookie => {
                    if (cookie.startsWith("__Host-MSAAUTH=")) {
                        foundHost = true;
                    }
                });
            }

            if (!foundHost) {
                console.log("[DEBUG] WARNING: __Host-MSAAUTH missing after OTP submission.");
                const fs = require('fs');
                fs.writeFileSync('error_flow3_checkpoint.html', loginData.data);
                console.log("[DEBUG] Saved response to error_flow3_checkpoint.html for verification.");
            }
        }

        // Flow 4: Email security OTP
        else if (obj.email && obj.pw && obj.secId && obj.secEmail) {
            // Placeholder: Flow 4 logic was not provided in the original snippet.
        }

        // Final cookie processing for all flows
        if (loginData?.headers?.["set-cookie"]) {
            loginData.headers["set-cookie"].forEach(cookie => {
                const [name, ...values] = cookie.split("=");
                if (name === "__Host-MSAAUTH") {
                    host = values.join("=").split(";").shift();
                    console.log(`Final host extracted: ${host}`);
                }
            });
        }

    } catch (error) {
        console.error("Error during login process:", error.message);
        throw error;
    }

    return host || null;
};
