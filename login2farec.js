const HttpClient = require("../process/HttpClient");
const crypto = require("crypto");
const generate = require("../../utils/generate.js");
const { domains } = require("../../../config.json");
const generateotp = require("./codefromsecret.js");
const { getEmailDescription } = require("../utils/getEmailDescription.js"); 

// Helper for human-like delays
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Anti-bot AJAX headers
const baseHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0',
    'Accept': 'application/json',
    'Accept-Language': 'nl,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'x-ms-apiVersion': '2',
    'x-ms-apiTransport': 'xhr',
    'X-Requested-With': 'XMLHttpRequest',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache'
};

// Parse ServerData from HTML
function parseServerData(html) {
    if (!html || typeof html !== "string") return null;
    const patterns = [
        /var\s+ServerData\s*=\s*(\{.*?\})\s*;/s,
        /var\s+ServerData=(\{.*?\})(?=;|$)/s,
        /"ServerData"\s*:\s*(\{.*?\})(?=,\s*"|\s*\})/s,
    ];
    for (const pattern of patterns) {
        const match = html.match(pattern);
        if (!match?.[1]) continue;
        try { return JSON.parse(match[1]); } catch (_) {}
    }
    return null;
}

// Decode URL token
function decodeToken(value) {
    if (!value || typeof value !== "string") return null;
    try { return decodeURIComponent(value); } catch (_) { return value; }
}

// Get 2FA proof ID
function getProofId(serverData) {
    const proofs = Array.isArray(serverData?.arrUserProofs) ? serverData.arrUserProofs : [];
    const priorities = [10, 11, 5]; 
    for (const type of priorities) {
        const proof = proofs.find((item) => Number(item?.type) === type);
        if (proof) return proof.data || proof.id || proof.display || ""; 
    }
    if (proofs.length > 0) return proofs[0].data || proofs[0].id || "";
    return "";
}

// Map error codes
function mapErrorCode(code) {
    if (code === "6001") return "tfa";
    if (code === "1218") return "same";
    return null;
}

module.exports = async (email, secretkey, recoveryCode) => {
    console.log(`[LOGIN_2FA_REC] Start: ${email}`);

    try {
        const httpClient = new HttpClient();
        
        // 1. Init session
        const resetResponse = await httpClient.get(
            `https://account.live.com/ResetPassword.aspx?wreply=https://login.live.com/oauth20_authorize.srf&mn=${encodeURIComponent(email)}`,
            { 
                headers: { 
                    ...baseHeaders, 
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Origin': 'https://account.live.com'
                },
                noproxy: true,
                validateStatus: () => true
            }
        );

        const html = resetResponse.data || "";
        if (typeof html !== "string" || html.includes("reset-password-signinname_en")) {
            console.log("[LOGIN_2FA_REC] Invalid email");
            return null;
        }

        const serverData = parseServerData(html);
        if (!serverData) return null;

        let token = decodeToken(serverData.sRecoveryToken);
        let apiCanary = serverData.apiCanary || serverData.canary || null;
        const uaid = crypto.randomBytes(16).toString("hex");

        if (!token || !apiCanary) return null;

        let headers = {
            ...baseHeaders,
            'Content-Type': 'application/json',
            'Referer': `https://account.live.com/ResetPassword.aspx?mn=${encodeURIComponent(email)}`,
            'Origin': 'https://account.live.com',
            'canary': apiCanary,
            'uiflvr': '1001',
            'scid': '100109',
            'hpgid': '201030',
            'uaid': uaid
        };

        // Update tokens dynamically to prevent Stale CSRF
        const updateSecurityTokens = (resData) => {
            if (resData.token) token = decodeToken(resData.token);
            if (resData.apiCanary) headers.canary = resData.apiCanary;
            else if (resData.canary) headers.canary = resData.canary;
        };

        await delay(1500);

        // 2. Verify App 2FA
        if (secretkey) {
            const { otp } = await generateotp(secretkey);
            if (otp) {
                let proofId = getProofId(serverData);
                console.log(`[LOGIN_2FA_REC] Verify App 2FA`);
                
                const verifyProofRes = await httpClient.post(
                    "https://account.live.com/API/Recovery/VerifyProof",
                    { code: otp, proofId: proofId, scid: 100109, token, uiflvr: 1001 },
                    { headers, noproxy: true, validateStatus: () => true }
                );

                const data = verifyProofRes.data || {};
                const proofError = mapErrorCode(data.error?.code || data.code);
                if (proofError) return proofError;
                
                updateSecurityTokens(data);
            }
        }

        await delay(2000);

        // 3. Verify Recovery Code
        console.log("[LOGIN_2FA_REC] Verify Recovery Code");
        const recTokenRes = await httpClient.post(
            "https://account.live.com/API/Recovery/VerifyRecoveryCode",
            { code: recoveryCode, recoveryCode, publicKey: "2CBB3761027476727BDDBC9DE02870BE01ED793A", scid: 100109, token, uiflvr: 1001 },
            { headers, noproxy: true, validateStatus: () => true }
        );

        const recData = recTokenRes.data || {};
        const verifyRecoveryError = mapErrorCode(recData.error?.code || recData.code);
        if (verifyRecoveryError) return verifyRecoveryError;
        if (!recData.token) return "invalid";

        updateSecurityTokens(recData);
        console.log("[LOGIN_2FA_REC] Recovery code OK");

        await delay(2000);

        // 4. Send OTP
        const secEmail = `${generate(16)}@${domains[0]}`;
        const newPassword = generate(16);

        console.log(`[LOGIN_2FA_REC] Send OTP to ${secEmail}`);
        const sendOttRes = await httpClient.post(
            "https://account.live.com/API/Recovery/SendOtt",
            { action: "VerifyNewProof", channel: "Email", cxt: "CA", proofId: secEmail, scid: 100109, token, uaid, uiflvr: 1001 },
            { headers, noproxy: true, validateStatus: () => true }
        );

        const sendData = sendOttRes.data || {};
        updateSecurityTokens(sendData);

        // 5. Wait for OTP
        console.log(`[LOGIN_2FA_REC] Waiting for OTP`);
        let otpCode = null;
        const startTime = Date.now();
        const deadline = startTime + 120000; 
        
        while (Date.now() < deadline) {
            try {
                otpCode = await Promise.race([
                    getEmailDescription(startTime, secEmail, true),
                    new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 5000))
                ]);
                if (otpCode) break;
            } catch (err) {}
            await delay(4000);
        }

        if (!otpCode) {
            console.log(`[LOGIN_2FA_REC] Failed to get OTP`);
            return null;
        }

        await delay(1000);

        // 6. Verify OTP
        console.log(`[LOGIN_2FA_REC] Verify OTP: ${otpCode}`);
        const verifyCodeRes = await httpClient.post(
            "https://account.live.com/API/Recovery/VerifyCode",
            { action: "VerifyOtc", code: otpCode, proofId: secEmail, scid: 100109, token, uaid, uiflvr: 1001 },
            { headers, noproxy: true, validateStatus: () => true }
        );

        const vCodeData = verifyCodeRes.data || {};
        updateSecurityTokens(vCodeData);

        await delay(1500);

        // 7. Recover User
        for (let attempt = 1; attempt <= 3; attempt++) {
            console.log(`[LOGIN_2FA_REC] RecoverUser ${attempt}/3`);
            try {
                const recoverUserRes = await httpClient.post(
                    "https://account.live.com/API/Recovery/RecoverUser",
                    { contactEmail: secEmail, contactEpid: "", password: newPassword, passwordExpiryEnabled: 0, publicKey: "2CBB3761027476727BDDBC9DE02870BE01ED793A", token, uaid },
                    { headers, noproxy: true, validateStatus: () => true }
                );

                const recUserData = recoverUserRes.data || {};
                const responseError = mapErrorCode(recUserData.error?.code || recUserData.code);
                if (responseError) return responseError;

                if (recUserData.apiCanary || recUserData.recoveryCode) {
                    console.log("[LOGIN_2FA_REC] RecoverUser SUCCESS");
                    return {
                        email2: email,
                        recoveryCode: recUserData.recoveryCode || recoveryCode,
                        secEmail,
                        password: newPassword,
                    };
                }
            } catch (error) {}
            if (attempt < 3) await delay(2000);
        }

        console.log("[LOGIN_2FA_REC] RecoverUser failed");
        return null;
    } catch (error) {
        console.error(`[LOGIN_2FA_REC] Fatal Error: ${error.message}`);
        return null;
    }
};
