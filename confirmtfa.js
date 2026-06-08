const decode = require('./decode');

module.exports = async function confirmtfa(axios, code, proof, rvtkn, apiCanary) {
  const decodedr = decodeURIComponent(rvtkn);

  // Extract dynamic uaid from axios cookie to maintain session consistency
  const cookieHeader = axios.defaults.headers?.Cookie || axios.defaults.headers?.cookie || "";
  const uaidMatch = cookieHeader.match(/uaid=([^;]+)/);
  const uaid = uaidMatch ? uaidMatch[1] : "b98750aea5644a548609bbcbfab874cb";

  try {
    // Prepare payload with dynamic uaid
    const requestData = {
      ProofId: proof,
      TotpCode: code,
      uiflvr: 1001,
      uaid: uaid,
      scid: 100109,
      hpgid: 200335
    };

    // Submit TOTP code for verification
    const response = await axios.post('https://account.live.com/API/AddVerifyTotp', requestData, {
      headers: {
        'Content-Type': 'application/json',
        'canary': apiCanary,
        'hpgid': '200335',
        'scid': '100109',
        'uiflvr': '1001',
        'uaid': uaid
      }
    });

    // Return retry state if Microsoft rejects the payload (missing apiCanary)
    if (!response.data?.apiCanary) {
      return 'retry';
    }

    const enableTfaUrl = `https://account.live.com/proofs/EnableTfa?mkt=en-gb&uaid=${uaid}&rvtkn=${decodedr}`;

    // Helper function to attempt enabling TFA with proxy
    const tryWithProxy = async () => {
      try {
        const tfarequest = await axios.post(
          enableTfaUrl,
          null,
          {
            proxy: true 
          }
        );
        return tfarequest;
      } catch (error) {
        throw new Error('Proxy request failed');
      }
    };

    let retries = 3;
    let tfarequest;

    // Execute proxy attempts
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        tfarequest = await tryWithProxy();
        if (tfarequest.status === 200) {
          return true;
        }
      } catch (error) {
        if (attempt === retries) {
          console.log('Max retries reached. Attempting without proxy...');
          break;
        }
        console.log(`Retry ${attempt} failed with proxy. Retrying...`);
      }
    }

    // Fallback attempt without proxy
    const tfarequestWithoutProxy = await axios.post(
      enableTfaUrl,
      null,
      {
        headers: {
          'Content-Type': 'application/json',
          'canary': apiCanary,
          'hpgid': '200335',
          'scid': '100109',
          'uiflvr': '1001',
          'uaid': uaid
        }
      }
    );

    if (tfarequestWithoutProxy.data?.error) {
      return false;
    }

    if (tfarequestWithoutProxy.status === 200) {
      return true;
    }

    return false;
  } catch (error) {
    console.error('Error during TFA confirmation:', error);
    return false;
  }
};
