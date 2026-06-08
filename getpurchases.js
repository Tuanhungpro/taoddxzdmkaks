// Fetch payment transactions from Microsoft API
async function getpurchases(axios, msatoken) {
  try {
    const response = await axios.get('https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentTransactions', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://account.microsoft.com/',
        'Content-Type': 'application/json',
        'Authorization': msatoken,
        'Origin': 'https://account.microsoft.com',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-site'
      }
    });
    
    // Return transaction data as string
    return JSON.stringify(response.data); 

  } catch (error) {
    // Log error and return null on failure
    console.error(`[Purchases] Error fetching purchases: ${error.message}`); 
    return null; 
  }
}

module.exports = getpurchases;
