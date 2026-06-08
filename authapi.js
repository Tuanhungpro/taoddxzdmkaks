/**
 * Sends the initial authentication payload to Microsoft's GetCredentialType API.
 * Leverages 'forceotclogin' to bypass 2FA/OTP requirements where possible.
 *
 * @param {Object} session - Axios instance with cookie jar support
 * @param {string} email - The email address to authenticate
 * @returns {Object|null} - The parsed JSON response containing credential info
 */
module.exports = async (session, email) => {
    const payload = {
        checkPhones: true,
        country: "",
        federationFlags: 3,
        flowToken: "-DgAlkPotvHRxxasQViSq!n6!RCUSpfUm9bdVClpM6KR98HGq7plohQHfFANfGn4P7PN2GnUuAtn6Nu3dwU!Tisic5PrgO7w8Rn*LCKKQhcTDUPMM2QJJdjr4QkcdUXmPnuK!JOqW7GdIx3*icazjg5ZaS8w1ily5GLFRwdvobIOBDZP11n4dWICmPafkNpj5fKAMg3!ZY2EhKB7pVJ8ir4A$",
        forceotclogin: false,
        isCookieBannerShown: true,
        isExternalFederationDisallowed: true,
        isFederationDisabled: true,
        isFidoSupported: false,
        isOtherIdpSupported: false,
        isRemoteConnectSupported: false,
        isRemoteNGCSupported: true,
        isSignup: false,
        otclogindisallowed: false,
        username: email
    };

    let emailInfo = null;

    // Loop twice: First payload triggers authenticator entropy, second forces email OTP if exists
    for (let i = 0; i < 2; i++) {
        try {
            const response = await session.post("https://login.live.com/GetCredentialType.srf", payload, {
                headers: {
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip, deflate, br, zstd",
                    "Content-Type": "application/json; charset=utf-8",
                    "Cookie": "MSPOK=$uuid-899fc7db-4aba-4e53-b33b-7b3268c26691",
                    "Referer": "https://login.live.com/",
                    "hpgact": "0",
                    "hpgid": "33"
                },
                maxRedirects: 10,
                validateStatus: () => true
            });

            // Ensure response data is treated as a JSON object
            emailInfo = typeof response.data === 'string' ? JSON.parse(response.data) : response.data;

            // Success condition: RemoteNgcParams is present
            if (emailInfo && emailInfo.Credentials && emailInfo.Credentials.RemoteNgcParams) {
                return emailInfo;
            }

            // Force OTC login flag for the second attempt if the first one requires it
            payload.forceotclogin = true;

        } catch (error) {
            // Suppress errors and return null to prevent application crash
            return null;
        }
    }

    return emailInfo;
};
