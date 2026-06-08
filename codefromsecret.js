const crypto = require('crypto');

/**
 * Generate a 6-digit TOTP based on the provided Base32 secret key.
 * @param {string} secretKey - The raw 2FA secret key.
 * @returns {Promise<Object>} Object containing the OTP and the next reset epoch.
 */
async function generateotp(secretKey) {
    try {
        // Validate input
        if (!secretKey || typeof secretKey !== 'string') {
            return { otp: null, nextResetEpoch: null };
        }

        // Sanitize input: remove spaces, hyphens, and convert to uppercase
        const formattedSecret = secretKey.replace(/[\s-]/g, "").toUpperCase();

        // Validate Base32 format
        if (!/^[A-Z2-7]+$/.test(formattedSecret)) {
            return { otp: null, nextResetEpoch: null };
        }

        // Convert Base32 characters to a binary string
        const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bits = "";
        for (let i = 0; i < formattedSecret.length; i++) {
            const val = base32chars.indexOf(formattedSecret.charAt(i));
            bits += val.toString(2).padStart(5, '0');
        }

        // Convert binary string to a Buffer array
        const hexArr = [];
        for (let i = 0; i + 8 <= bits.length; i += 8) {
            hexArr.push(parseInt(bits.substr(i, 8), 2));
        }
        const keyBuffer = Buffer.from(hexArr);

        // Calculate time steps (30 seconds per step)
        const expiry = 30;
        const epoch = Math.floor(Date.now() / 1000);
        const timeStr = Math.floor(epoch / expiry).toString(16).padStart(16, '0');
        const timeBuffer = Buffer.from(timeStr, 'hex');

        // Create HMAC-SHA1 signature using the native crypto module
        const hmac = crypto.createHmac('sha1', keyBuffer);
        hmac.update(timeBuffer);
        const hmacResult = hmac.digest();

        // Extract the dynamic offset
        const offset = hmacResult[hmacResult.length - 1] & 0xf;
        
        // Calculate the 6-digit OTP value
        const code = (
            ((hmacResult[offset] & 0x7f) << 24) |
            ((hmacResult[offset + 1] & 0xff) << 16) |
            ((hmacResult[offset + 2] & 0xff) << 8) |
            (hmacResult[offset + 3] & 0xff)
        ) % 1000000;

        // Ensure the OTP is exactly 6 digits by padding with leading zeros if necessary
        const otp = code.toString().padStart(6, '0');
        
        // Calculate the next epoch time when the OTP will reset
        const nextResetEpoch = Math.floor(epoch / expiry) * expiry + expiry;

        return { otp, nextResetEpoch };

    } catch (error) {
        console.error("Error generating OTP:", error.message);
        return { otp: null, nextResetEpoch: null };
    }
}

module.exports = generateotp;
