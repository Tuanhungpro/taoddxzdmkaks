const cheerio = require('cheerio');

/**
 * Fetches basic account information (OGO data).
 * Includes WAF bypass and robust payload parsing.
 * @param {Object} axios - Authenticated Axios instance.
 * @returns {Promise<string|null>} - JSON string of account info or fallback.
 */
async function getogo(axios) {
    try {
        // 1. Synchronize User-Agent dynamically to prevent WAF blocks
        const userAgent = (axios.defaults?.headers?.common?.['User-Agent']) 
                          || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

        // 2. Fetch profile page to scrape CSRF token securely
        const profilePage = await axios.get("https://account.microsoft.com/profile", {
            headers: { 
                'User-Agent': userAgent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none'
            }
        });
        
        // Extract Request Verification Token using multiple fallbacks
        let token = profilePage.data?.match(/name="__RequestVerificationToken"\s*value="([^"]+)"/i)?.[1]
                    || profilePage.data?.match(/"__RequestVerificationToken"\s*:\s*"([^"]+)"/)?.[1]
                    || axios.defaults?.headers?.common?.['__RequestVerificationToken'] 
                    || '';

        // 3. Call the Personal Info API with the scraped Verification Token
        const response = await axios.get(`https://account.microsoft.com/profile/api/v1/personal-info`, {
            headers: {
                'User-Agent': userAgent,
                'Accept': 'application/json, text/plain, */*',
                'X-Requested-With': 'XMLHttpRequest',
                '__RequestVerificationToken': token,
                'Referer': 'https://account.microsoft.com/profile'
            }
        });

        // 4. Extract data robustly to prevent 'Unknown' values
        if (response?.data && typeof response.data === 'object') {
            let data = response.data;
            
            // Unwrap nested payloads if Microsoft changes the structure
            if (data.personalInfo) data = data.personalInfo;
            else if (data.payload) data = data.payload;

            // Support modern and legacy keys (camelCase, PascalCase, snake_case)
            const email = (data.emails && data.emails.length > 0) ? data.emails[0] : (data.signInEmail || data.Email || "Unknown");
            const firstname = data.firstName || data.FirstName || data.first_name || "Unknown";
            const lastname = data.lastName || data.LastName || data.last_name || "Unknown";
            
            let birthday = "Unknown";
            if (data.birthDate && data.birthDate.day) {
                birthday = `${data.birthDate.day}/${data.birthDate.month}/${data.birthDate.year}`;
            } else if (data.birthday || data.Birthday) {
                birthday = data.birthday || data.Birthday; 
            }

            const country = data.country || data.Country || data.region || "Unknown";
            
            // Return formatted JSON string
            return JSON.stringify({ email, firstname, lastname, birthday, country }, null, 2);
        }
        
        return null;

    } catch (error) {
        // 5. Handle WAF blocks or network errors gracefully
        console.error(`[-] [GET_OGO] Error:`, error.response?.status || error.message);
        
        const fallbackData = {
            email: "Failed to fetch",
            firstname: "Failed to fetch",
            lastname: "Failed to fetch",
            birthday: "Failed to fetch",
            country: "Failed to fetch"
        };
        
        return JSON.stringify(fallbackData, null, 2);
    }
}

module.exports = getogo;
