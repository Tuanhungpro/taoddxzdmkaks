/**
 * Fetch family roster data.
 * @param {Object} axios - Authenticated axios instance
 * @returns {Promise<string|null>} - Stringified family JSON or null
 */
module.exports = async (axios) => {
    try {
        // Sync User-Agent to bypass WAF
        const userAgent = (axios.defaults?.headers?.common?.['User-Agent']) 
                          || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

        // Fetch family API
        const response = await axios.get("https://account.microsoft.com/family/api/roster", {
            headers: {
                "User-Agent": userAgent,
                "Accept": "application/json, text/plain, */*",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://account.microsoft.com/family/home",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin"
            },
            validateStatus: () => true // Prevent throw on 4xx/5xx
        });
        
        if (response.status !== 200) return null;

        const data = response.data;
        let members = [];
        
        // Extract members array safely
        if (Array.isArray(data)) {
            members = data;
        } else if (data?.members && Array.isArray(data.members)) {
            members = data.members;
        } else if (data?.familyGroup?.members && Array.isArray(data.familyGroup.members)) {
            members = data.familyGroup.members;
        } else if (data?.Members && Array.isArray(data.Members)) {
            members = data.Members;
        }

        // Stringify the array to safely save and display
        if (members && members.length > 0) {
            return JSON.stringify(members);
        }
        
        return null;

    } catch (error) {
        console.error("[-] [GET_FAMILY] Error:", error.message);
        return null;
    }
};
