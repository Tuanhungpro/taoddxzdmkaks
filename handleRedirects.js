const fs = require('fs');
const path = require('path');

/**
 * Automatically resolves intermediary Microsoft pages (KMSI, Notice, Family).
 * Extracts hidden inputs and submits them to continue the auth flow.
 * Includes a fallback to dump HTML for debugging unrecognized pages.
 *
 * @param {Object} session - Axios instance with cookie jar support
 * @param {string} initialUrl - The starting redirect URL
 * @returns {boolean} - True if successfully navigated to the final account page
 */
module.exports = async (session, initialUrl) => {
    let currentUrl = initialUrl;
    let maxLoops = 5;

    while (currentUrl && maxLoops > 0) {
        maxLoops--;

        try {
            // Ensure URL is absolute
            if (!currentUrl.startsWith('http')) {
                currentUrl = new URL(currentUrl, "https://login.live.com").href;
            }

            const response = await session.get(currentUrl, {
                headers: {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": "https://login.live.com/"
                },
                maxRedirects: 0,
                validateStatus: () => true
            });

            // Follow HTTP 302 redirects
            if (response.headers.location) {
                currentUrl = response.headers.location;
                continue;
            }

            const html = response.data || "";

            // Check if we hit the final success destination
            if (currentUrl.includes("account.microsoft.com") || html.includes("Sign out")) {
                return true;
            }

            // Parse HTML for intermediary forms (e.g., KMSI, Notices)
            const actionMatch = html.match(/<form[^>]+action=['"]([^'"]+)['"]/i);
            
            if (actionMatch) {
                let actionUrl = actionMatch[1].replace(/&amp;/g, '&');
                let hiddenInputs = {};
                let inputRegex = /<input[^>]+>/gi;
                let inputMatch;
                
                // Extract all hidden fields required to proceed
                while ((inputMatch = inputRegex.exec(html)) !== null) {
                    let inputHtml = inputMatch[0];
                    if (/type=['"]?(hidden|submit)['"]?/i.test(inputHtml)) {
                        let nameM = inputHtml.match(/name=['"]([^'"]+)['"]/i);
                        let valM = inputHtml.match(/value=['"]([^'"]*)['"]/i) || ["", ""];
                        if (nameM) hiddenInputs[nameM[1]] = valM[1] || "";
                    }
                }

                // Auto-accept "Keep me signed in" (KMSI) if prompted
                if (html.includes('Kmsi')) {
                    hiddenInputs['LoginOptions'] = '3';
                }

                if (Object.keys(hiddenInputs).length > 0) {
                    const postRes = await session.post(actionUrl, new URLSearchParams(hiddenInputs).toString(), {
                        headers: {
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Referer": currentUrl
                        },
                        maxRedirects: 0,
                        validateStatus: () => true
                    });

                    // Update currentUrl for the next iteration
                    currentUrl = postRes.headers.location || null;
                    
                    if (!currentUrl) {
                        const nextFormMatch = (postRes.data || "").match(/<form[^>]+action=['"]([^'"]+)['"]/i);
                        if (nextFormMatch) currentUrl = nextFormMatch[1];
                    }
                    continue;
                }
            }

            // Unrecognized trap or dead end - Save debug file to analyze
            const errorFile = path.join(process.cwd(), `error_redirect_${Date.now()}.html`);
            fs.writeFileSync(errorFile, html, 'utf-8');
            console.log(`[-] Redirect blocked. Dumped HTML to: ${errorFile}`);
            break;

        } catch (error) {
            console.log(`[X] Error in handleRedirects: ${error.message}`);
            break;
        }
    }

    return false;
};
