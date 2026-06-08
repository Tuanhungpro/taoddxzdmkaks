async function getAliases(axios) {
    // Check if the required authentication cookie is present before making the request
    if (!axios.getCookie(`AMRPSSecAuth`)) return false;

    try {
        // Fetch the alias management page HTML
        let aliasData = await axios.get(`https://account.live.com/names/manage`);

        const result = {
            aliases: [],
            canary: null,
            primary: null
        };

        // Extract the canary token from the HTML input field using regex
        const canaryMatch = aliasData.data.match(/<input type="hidden" id="canary" name="canary" value="([^"]+)" \/>/);
        if (canaryMatch) {
            result.canary = canaryMatch[1];
        }

        // Extract the JSON object containing account data from the inline script
        const jsObjectMatch = aliasData.data.match(/var\s+t0\s*=\s*({[^;]+})/);
        if (jsObjectMatch && jsObjectMatch[1]) {
            try {
                const accountData = JSON.parse(jsObjectMatch[1]);

                // Safely extract phone aliases, checking for both string and object formats
                if (accountData?.WLXAccount?.addAlias?.phoneAliases) {
                    const phoneAliases = accountData.WLXAccount.addAlias.phoneAliases;
                    phoneAliases.forEach(item => {
                        if (typeof item === 'string') {
                            result.aliases.push(item);
                        } else if (item && item.name) {
                            result.aliases.push(item.name);
                        }
                    });
                }

                // Safely extract email aliases (mxAliases), checking for both string and object formats
                if (accountData?.WLXAccount?.manageNames?.mxAliases) {
                    const mxAliases = accountData.WLXAccount.manageNames.mxAliases;
                    mxAliases.forEach(item => {
                        if (typeof item === 'string') {
                            result.aliases.push(item);
                        } else if (item && item.name) {
                            result.aliases.push(item.name);
                        }
                    });
                }

                // Extract the primary member name (primary email/alias)
                if (accountData?.WLXAccount?.accountManagement?.membername) {
                    result.primary = accountData.WLXAccount.accountManagement.membername;

                    // Ensure the primary alias is also included in the general aliases array
                    if (!result.aliases.includes(result.primary)) {
                        result.aliases.push(result.primary);
                    }
                }
            } catch (jsonError) {
                console.log(`[ERROR] JSON parse failed in getAliases: ${jsonError.message}`);
            }
        }

        // Return the structured array containing the aliases, canary token, and primary alias
        return [result.aliases, result.canary, result.primary];

    } catch (error) {
        // Log and re-throw the error if the request fails
        console.error(`[ERROR] Error fetching aliases: ${error.message}`);
        throw error;
    }
}

module.exports = getAliases;
