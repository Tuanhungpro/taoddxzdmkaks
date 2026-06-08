/**
 * Removes all OAuth applications (Consents)
 * @param {Object} axios - HttpClient instance
 * @returns {Promise<number>} - Number of removed apps
 */
module.exports = async (axios) => {
    try {
        // Fetch the Consent Manage page HTML
        const { data: htmlData } = await axios.get("https://account.live.com/consent/Manage?guat=1", {
            headers: {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Referer": "https://account.microsoft.com/"
            }
        });

        // Extract OAuth client IDs
        const clientIdRegex = /data-clientid="([^"]+)"/gi;
        const clientIds = [];
        let match;
        
        while ((match = clientIdRegex.exec(htmlData)) !== null) {
            clientIds.push(match[1]);
        }

        // Return 0 if no apps found
        if (clientIds.length === 0) {
            console.log("[OAUTH] No OAuth apps found.");
            return 0;
        }

        console.log(`[OAUTH] Found ${clientIds.length} apps. Removing...`);

        // Extract canary token for CSRF bypass
        const canaryMatch = htmlData.match(/name="canary"\s+id="canary"\s+value="([^"]+)"/i) || 
                            htmlData.match(/id="canary"\s+name="canary"\s+value="([^"]+)"/i);
        const canary = canaryMatch ? canaryMatch[1] : "";

        let removedCount = 0;

        // Process removal requests concurrently
        const removePromises = clientIds.map(async (clientId) => {
            try {
                const payload = new URLSearchParams();
                payload.append("canary", canary);
                payload.append("client_id", clientId);

                // Send POST request to remove specific client_id
                await axios.post("https://account.live.com/consent/Remove", payload.toString(), {
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://account.live.com",
                        "Referer": "https://account.live.com/consent/Manage"
                    }
                });
                
                removedCount++;
                console.log(`[OAUTH] Removed: ${clientId}`);
            } catch (err) {
                console.log(`[OAUTH] Failed to remove ${clientId}: ${err.message}`);
            }
        });

        // Wait for all removal requests to finish
        await Promise.all(removePromises);
        
        return removedCount;

    } catch (error) {
        console.error("[OAUTH] Error during removal:", error.message);
        return 0;
    }
};

