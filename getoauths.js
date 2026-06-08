/**
 * Fetches the connected OAuth applications (Consents) linked to the Microsoft account.
 * Uses the authenticated axios instance to retrieve the HTML and extract app data.
 * @param {Object} axios - The authenticated and configured axios instance.
 * @returns {Promise<string|null>} - A stringified JSON array of OAuth apps, or null if empty.
 */
module.exports = async (axios) => {
    try {
        // Step 1: Fetch the Consent Manage page to grab the HTML containing the connected apps
        const uatRequest = await axios.get("https://account.live.com/consent/Manage?guat=1", {
            headers: {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Referer": "https://account.microsoft.com/"
            }
        });

        // Step 2: Define regular expressions to extract Client IDs and Application Names
        const clientIdRegex = /data-clientid="([^"]+)"/gi;
        
        // We make the app name regex slightly more flexible in case Microsoft adds extra attributes to the div
        const appNameRegex = /<div[^>]*class="consentManageAppName"[^>]*>([^<]+)<\/div>/gi;
        
        const clientIds = [];
        const oauths = [];
        let match;

        // Step 3: Extract all Client IDs from the raw HTML
        while ((match = clientIdRegex.exec(uatRequest.data)) !== null) {
            clientIds.push(match[1]);
        }
        
        // Step 4: Extract all Application Names from the raw HTML
        while ((match = appNameRegex.exec(uatRequest.data)) !== null) {
            // Trim whitespace to ensure clean names
            oauths.push(match[1].trim());
        }

        // Step 5: Check if any apps were found. If not, return null to save DB space.
        if (clientIds.length === 0) {
            console.log("[-] [GET_OAUTHS] No OAuth apps found on this account.");
            return null; 
        }

        // Step 6: Map the extracted IDs and Names together into an array of objects
        const oauthData = clientIds.map((id, index) => ({
            clientId: id,
            appName: oauths[index] || "Unknown App" // Fallback name if regex misses it
        }));

        console.log(`[*] [GET_OAUTHS] Successfully fetched ${oauthData.length} OAuth apps.`);

        // Step 7: Return the data as a JSON string to be stored easily in the SQLite database
        // Example output: '[{"clientId":"xyz...","appName":"Minecraft"}]'
        return JSON.stringify(oauthData);
        
    } catch (error) {
        // Catch network errors or API changes silently without crashing the main process
        console.error("[-] [GET_OAUTHS] Error fetching OAuth data:", error.response ? error.response.status : error.message);
        return null;
    }
};
 