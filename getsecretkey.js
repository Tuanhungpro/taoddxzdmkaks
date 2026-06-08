module.exports = async function getSecretKey(axios) {
    try {
        // Extract dynamic uaid from axios cookie to prevent anti-bot trigger
        const cookieHeader = axios.defaults.headers?.Cookie || axios.defaults.headers?.cookie || "";
        const uaidMatch = cookieHeader.match(/uaid=([^;]+)/);
        const uaid = uaidMatch ? uaidMatch[1] : "489c69cebc8e46bdbffc31d0b05eb727";

        // Construct URL with dynamic uaid
        const url = `https://account.live.com/proofs/Add?mkt=en-gb&apt=2%7c1%7c3&uaid=${uaid}&orc=1&rc=1&mpcxt=CatA`;

        const response = await axios.get(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-GB,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": "https://account.live.com/proofs/EnableTfa",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1",
                "Priority": "u=0, i",
                "TE": "trailers",
            }
        });

        const htmlData = response.data;
        const lines = htmlData.split('\n');

        let secretKey = '';
        let proof = '';
        let rvtkn = '';

        // Extract Secret Key
        const secretKeyLine = lines.find(line => line.includes('Secret key:'));
        if (secretKeyLine) {
            const secretKeyRegex = /<span class="dirltr bold">([^<]+)<\/span>/;
            const match = secretKeyLine.match(secretKeyRegex);
            if (match && match[1]) {
                secretKey = match[1].replace(/&nbsp;/g, ' ').trim();
            }
        }

        // Extract Proof ID
        const proofLine = lines.find(line => line.includes('name="ProofId"'));
        if (proofLine) {
            const proofRegex = /<input[^>]+id="ProofId"[^>]+value="([^"]+)"/;
            const proofMatch = proofLine.match(proofRegex);
            if (proofMatch && proofMatch[1]) {
                proof = proofMatch[1];
            }
        }

        // Extract Routing Token (rvtkn)
        const rvtknRegex = /rvtkn=([^"]+)/;
        const rvtknMatch = htmlData.match(rvtknRegex);
        if (rvtknMatch && rvtknMatch[1]) {
            rvtkn = rvtknMatch[1];
        }

        // Return nulls if any critical component is missing
        if (!secretKey || !proof || !rvtkn) {
            return { secretKey: null, proof: null, rvtkn: null };
        }

        return { secretKey, proof, rvtkn };
    } catch (error) {
        // Silent catch to prevent crashing the main flow
        return { secretKey: null, proof: null, rvtkn: null };
    }
};
