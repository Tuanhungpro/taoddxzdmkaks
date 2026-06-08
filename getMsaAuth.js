/**
 * Submits the full extracted payload to Microsoft's dynamic urlPost.
 * Prevents bot detection by maintaining session context and all hidden inputs.
 *
 * @param {Object} session - Axios instance with cookie jar support
 * @param {string} urlPost - Dynamic POST URL extracted from the login page
 * @param {Object} payloadObj - Extracted hidden inputs combined with credentials
 * @returns {Promise<string|null>} - The next redirect URL or null on failure
 */
module.exports = async (session, urlPost, payloadObj) => {
    // Convert the entire object of hidden inputs and credentials into a form string
    const payload = new URLSearchParams(payloadObj).toString();
    
    // Use the dynamic URL to maintain session context, fallback to static if missing
    const targetUrl = urlPost || "https://login.live.com/ppsecure/post.srf";

    try {
        const response = await session.post(targetUrl, payload, {
            headers: {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://login.live.com",
                "Referer": "https://login.live.com/",
                "Upgrade-Insecure-Requests": "1"
            },
            // CRITICAL: Stop redirects to capture the exact Next URL and Set-Cookie headers
            maxRedirects: 0, 
            validateStatus: (status) => status >= 200 && status < 400
        });

        const redirectUrl = response.headers.location;
        const html = response.data || "";

        // Scenario 1: Standard HTTP 302 Redirect
        if (redirectUrl) {
            return redirectUrl.split('?')[0];
        }

        // Scenario 2: Microsoft embeds the redirect URL inside an HTML form or JSON object
        const embeddedUrlMatch = html.match(/<form[^>]+action=['"]([^'"]+)['"]/i) || html.match(/"urlPost"\s*:\s*"([^"]+)"/i);
        if (embeddedUrlMatch && embeddedUrlMatch[1]) {
            return embeddedUrlMatch[1].replace(/&amp;/g, '&');
        }

        // Login failed, returned to sign-in, or unrecognized response format
        return null;

    } catch (error) {
        // Suppress errors and return null to safely exit the flow
        return null;
    }
};
