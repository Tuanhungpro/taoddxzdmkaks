const cheerio = require('cheerio');
const initCycleTLS = require('cycletls');

/**
 * Removes an email alias from a Microsoft account.
 * Uses CycleTLS to bypass WAF shadowbans and verifies removal via DOM check.
 */
module.exports = async (axiosClient, name, externalCanary) => {
    let cycletls;
    try {
        console.log(`[REMOVE_ALIAS] Attempting to remove alias via CycleTLS: ${name}`);
        
        // Initialize TLS client
        cycletls = await initCycleTLS();

        // Extract session cookies safely from the main axios instance
        const currentCookie = axiosClient.defaults?.headers?.common?.Cookie || axiosClient.defaults?.headers?.Cookie || "";

        const baseHeaders = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            "Sec-Ch-Ua": '"Not A(Brand";v="8", "Chromium";v="132"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Referer": "https://account.microsoft.com/",
            "Cookie": currentCookie
        };

        // Step 1: Fetch manage page to obtain a fresh canary token
        let manageRes = await cycletls("https://account.live.com/names/manage", {
            headers: baseHeaders
        }, 'get');

        let html = manageRes.body || "";
        const $ = cheerio.load(html);
        
        let freshCanary = $('input[name="canary"]').val() || (html.match(/"sCanary"\s*:\s*"([^"]+)"/i) || [])[1] || externalCanary;

        if (!freshCanary) {
            console.log(`[REMOVE_ALIAS] [FAILED] Could not retrieve fresh canary.`);
            return false;
        }

        // Step 2: Send POST request to remove the alias
        const postData = `canary=${encodeURIComponent(freshCanary)}&action=RemoveAlias&aliasName=${encodeURIComponent(name)}&displayName=${encodeURIComponent(name)}`;

        await cycletls("https://account.live.com/names/manage", {
            headers: {
                ...baseHeaders,
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://account.live.com",
                "Referer": "https://account.live.com/names/manage",
                "Upgrade-Insecure-Requests": "1"
            },
            body: postData
        }, 'post');

        // Wait briefly for Microsoft's database to sync
        await new Promise(resolve => setTimeout(resolve, 1500));

        // Step 3: Strict Verification (Source of Truth)
        // Check the manage page again to confirm the alias is actually gone
        let verifyRes = await cycletls("https://account.live.com/names/manage", {
            headers: {
                ...baseHeaders,
                "Referer": "https://account.live.com/names/manage"
            }
        }, 'get');

        let verifyHtml = verifyRes.body || "";

        // If the alias string no longer exists in the body, removal was successful
        if (!verifyHtml.includes(`${name}`)) {
            console.log(`[REMOVE_ALIAS] [SUCCESS] Removed ${name} successfully.`);
            return true;
        } else {
            console.log(`[REMOVE_ALIAS] [FAILED] Alias still exists. Microsoft blocked the removal silently.`);
            return false;
        }

    } catch (error) {
        console.log(`[REMOVE_ALIAS] [ERROR] ${error.message}`);
        return false;
    } finally {
        // Prevent memory leaks by properly exiting the CycleTLS instance
        if (cycletls) cycletls.exit();
    }
};
