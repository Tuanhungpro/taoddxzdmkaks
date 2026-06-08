const axios = require("axios");

module.exports = async () => {
  try {
    // Initialize as an empty string instead of an array to prevent string concatenation bugs
    let cookies = ""; 

    // CRITICAL FIX: Use the official Xbox/Minecraft OAuth2 authorization URL instead of the bare login.live.com.
    // This provides the necessary context to Microsoft so it knows where to redirect after OTP verification,
    // completely fixing the "Microsoft account is unavailable from this site" error.
    const AUTH_URL = "https://login.live.com/oauth20_authorize.srf?client_id=00000000402b5328&response_type=code&scope=service%3A%3Auser.auth.xboxlive.com%3A%3AMBI_SSL&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf";

    const data = await axios({
      method: "GET",
      url: AUTH_URL,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive'
      }
    });
    
    // 1. Extract Initial Cookies from the response headers
    let c = data.headers["set-cookie"];
    if (c) {
      for (let co of c) {
        cookies += co.split(";")[0] + "; ";
      }
    }
    
    // Regex pattern to extract the specific POST link if available
    const linkRegex = /https:\/\/login.live.com\/ppsecure\/post.srf\?contextid=[0-9a-zA-Z]{1,100}&opid=[0-9a-zA-Z]{1,100}&bk=[a-zA-Z0-9]{1,100}&uaid=[0-9a-zA-Z]{1,100}\&pid=0/g;
    let ppft = null;
    let loginLink = null;
    
    // 2. Extract PPFT (Using robust methods including ServerData JSON parsing and DOM regex fallbacks)
    try {
      // Attempt to parse from the embedded ServerData JSON object first (Modern MS Layout)
      const serverDataMatch = data.data.match(/var ServerData = ({.*?});/s);
      if (serverDataMatch) {
        const serverData = JSON.parse(serverDataMatch[1]);
        if (serverData.sFTTag) {
          const ppftMatch = serverData.sFTTag.match(/value="([^"]*)"/);
          if (ppftMatch) {
            ppft = ppftMatch[1];
          }
        }
      }
      
      // Fallback 1: Standard input tag extraction
      if (!ppft) {
        const ppftRegex = /name="PPFT"[^>]*value="([^"]*)"/;
        const ppftMatch = data.data.match(ppftRegex);
        if (ppftMatch) {
          ppft = ppftMatch[1];
        }
      }
      
      // Fallback 2: Inverted attributes input tag extraction
      if (!ppft) {
        const ppftRegex2 = /value="([^"]*)"[^>]*name="PPFT"/;
        const ppftMatch2 = data.data.match(ppftRegex2);
        if (ppftMatch2) {
          ppft = ppftMatch2[1];
        }
      }
      
      // Extract the POST login link if present in the document
      const linkMatch = data.data.match(linkRegex);
      if (linkMatch) {
        loginLink = linkMatch[0];
      }
      
    } catch (error) {
      console.error('[getLiveData] Error parsing Microsoft login data:', error.message);
      
      // Final desperate fallback if JSON parsing crashes entirely
      const ppftRegex = /value="([^"]*)"/;
      const ppftMatch = data.data.match(ppftRegex);
      if (ppftMatch) {
        ppft = ppftMatch[1];
      }
      
      const linkMatch = data.data.match(linkRegex);
      if (linkMatch) {
        loginLink = linkMatch[0];
      }
    }

    // 3. Final validation before returning the data
    if (!ppft) {
      console.error('[getLiveData] Failed to extract PPFT from Microsoft login page.');
      return null;
    }

    return {
      loginLink: loginLink,
      ppft: ppft,
      cookies: cookies
    };
    
  } catch (error) {
    console.error('[getLiveData] Failed to get live data:', error.message);
    return null;
  }
};
