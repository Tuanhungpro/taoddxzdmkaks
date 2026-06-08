const getsecretKey = require("./getsecretkey");
const generateotp = require("./codefromsecret");
const confirmtfa = require("./confirmtfa");

async function addzyger(axios, apiCanary) {
  try {
    // Fetch secret key, proof ID, and routing token
    let { secretKey, proof, rvtkn } = await getsecretKey(axios);
    
    if (!secretKey || !proof) {
      console.log("Missing secretKey or proof.");
      return { success: false, secretKey }; 
    }

    let code;

    // Generate initial OTP
    let data = await generateotp(secretKey);
    if (data && data.otp) {
      code = data.otp; 
    }

    // Attempt to confirm TFA
    let tfaconfirmed = await confirmtfa(axios, code, proof, rvtkn, apiCanary);
    
    // Handle retry state if the first attempt fails or is rejected
    if (tfaconfirmed === "retry") {
      console.log("Invalid OTP or session rejected, retrying...");
      data = await generateotp(secretKey); 
      if (data && data.otp) {
        code = data.otp; 
      }
      tfaconfirmed = await confirmtfa(axios, code, proof, rvtkn, apiCanary);
    }
  
    // Return success if TFA is confirmed
    if (tfaconfirmed === true) {
      console.log("TFA confirmed successfully.");
      return { success: true, secretKey }; 
    }

    // Fallback for failed confirmation or persistent retry states
    console.log("TFA confirmation failed.");
    return { success: false, secretKey }; 

  } catch (error) {
    console.error("Error in addzyger flow:", error);
    return { success: false, secretKey: null }; 
  }
}

module.exports = addzyger;
