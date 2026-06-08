// Fetch user subscriptions from Microsoft API
async function getsubscriptions(axios) {
  try {
    const response = await axios.get('https://account.microsoft.com/services/api/subscriptions', {
      params: {
        'excludeWindowsStoreInstallOptions': 'false',
        'excludeLegacySubscriptions': 'true',
        'isReact': 'true',
        'includeCmsData': 'false'
      },
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'X-Requested-With': 'XMLHttpRequest',
        'Connection': 'keep-alive',
        'Referer': 'https://account.microsoft.com/?lang=en-US',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
      }
    });

    // Return full data object to prevent crashes on empty subscriptions
    const subscriptions = response.data;
    return JSON.stringify(subscriptions, null, 2); 
    
  } catch (error) {
    // Log error and return null on failure
    console.error(`[Subscriptions] Error fetching subscriptions: ${error.message}`);
    return null;
  }
}

module.exports = getsubscriptions;
