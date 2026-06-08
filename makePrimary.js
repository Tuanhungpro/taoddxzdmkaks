/**
 * Dummy MakePrimary script.
 * The Python worker (alias_worker.py) already handled the Make Primary step 
 * simultaneously with Add Alias to prevent Microsoft API Race Condition (Error 500).
 * This file ensures the main bot execution flow continues smoothly without breaking.
 */
module.exports = async (axiosClient, name, apicanary) => {
    return new Promise((resolve) => {
        // Log the bypass action to the console
        console.log(`[MAKE_PRIMARY] Skipped! Alias ${name} was already made primary by the Python worker.`);
        
        // Resolve true to allow the next phase (Remove Alias) to execute
        resolve(true);
    });
};
