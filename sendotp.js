const HttpClient = require("../process/HttpClient");
const otpmethod2 = require("../utils/otp2");

/**
 * Sends an OTP (One Time Password) request to Microsoft.
 * Proxies will now be automatically applied via HttpClient if configured.
 */
async function sendotp(email, secId) {
    console.log(`[SendOTP Debug] Starting OTP process for email: ${email}`);

    // Prepare the OTP method for the specific email
    try {
        console.log(`[SendOTP Debug] Executing otpmethod2 setup...`);
        await otpmethod2(email);
    } catch (error) {
        console.error(`[SendOTP Error] Failed during otpmethod2 setup:`, error.message);
        return false;
    }

    try {
        const httpClient = new HttpClient();
        console.log(`[SendOTP Debug] HttpClient initialized. Fetching initial session from Microsoft...`);

        // 1. Send GET request to Microsoft Login to grab fresh Cookies and a live FlowToken
        // Note: Removed noproxy flag to allow HttpClient to use configured proxies.
        const initResponse = await httpClient.get("https://login.live.com/", {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            }
        });

        console.log(`[SendOTP Debug] Initial GET request successful. Status: ${initResponse.status}`);
        const html = initResponse.data || "";
        
        // Optional WAF check log. Uncomment the next line if you need to see the raw HTML returned.
        // console.log(`[SendOTP Debug] HTML Response Snippet: ${html.substring(0, 300)}...`);
        
        // 2. Extract the dynamic flow token
        let dynamicToken = null;
        const tokenMatch = html.match(/name="flowToken"[^>]*value="([^"]+)"/i) 
                        || html.match(/id="flowToken"[^>]*value="([^"]+)"/i)
                        || html.match(/name="PPFT"[^>]*value="([^"]+)"/i);

        if (tokenMatch && tokenMatch[1]) {
            dynamicToken = tokenMatch[1]; 
            console.log(`[SendOTP Debug] Successfully extracted fresh FlowToken.`);
        } else {
            console.warn(`[SendOTP Debug] Warning: Could not extract dynamic token. Microsoft might have blocked the IP or changed HTML structure. Falling back to default token.`);
            dynamicToken = "-DvTDvmRgphmpW9oJRrYLB1YGD*aPHnUeOf3zvwQABaxrG8WwdFr6jD12imzrE3D2AhdfsKbazoW5G0AvCvO9Thz!9VzxnGUlAbtWqwft34nll3cx2ge2pRYsrK5Sq6BtZbObPlJ2tDiwu3gRDgBjzFldYn*rt9By5D!6QUKFoC8pFtKS949tDFokpG0BpT07ig$$";
        }

        console.log(`[SendOTP Debug] Preparing POST payload targeting Security ID: ${secId}`);

        // 3. Prepare the URL-encoded payload
        const postData = `login=${encodeURIComponent(email)}&flowtoken=${encodeURIComponent(dynamicToken)}&purpose=eOTT_OtcLogin&channel=Email&AltEmailE=${encodeURIComponent(secId)}`;

        console.log(`[SendOTP Debug] Triggering OTP email request...`);

        // 4. Send the POST request to trigger the Microsoft OTP email
        // Note: Removed noproxy flag here as well.
        const response = await httpClient.post(
            "https://login.live.com/GetOneTimeCode.srf",
            postData,
            {
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
                }
            }
        );

        console.log(`[SendOTP Debug] POST request completed successfully. Status: ${response.status}`);
        return true;

    } catch (error) {
        // Catch and log network timeouts, WAF blocks, or server errors
        console.error(`[SendOTP Error] Network or Request Failure:`, error.message);
        
        if (error.response) {
            console.error(`[SendOTP Error] Response Status: ${error.response.status}`);
            // Uncomment the next line if you need to see exactly what Microsoft's server replied with on error
            // console.error(`[SendOTP Error] Response Data:`, error.response.data);
        }
        
        return false;
    }
}

module.exports = sendotp;
