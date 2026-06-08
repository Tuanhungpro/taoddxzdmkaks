/**
 * Fetch Microsoft family roster and format for Discord
 * @param {Object} axios - Authenticated axios instance
 * @returns {Promise<string>}
 */
module.exports = async function getfamilydata(axios) {
    try {
        // Set User-Agent
        const userAgent = (axios.defaults?.headers?.common?.['User-Agent']) 
                          || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

        // Fetch family roster
        const resp = await axios.get("https://account.microsoft.com/family/api/roster", {
            headers: {
                "User-Agent": userAgent,
                "Accept": "application/json, text/plain, */*",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://account.microsoft.com/family/home",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin"
            }
        });

        const data = resp.data;
        
        // Extract members array safely
        let members = [];
        if (Array.isArray(data)) members = data;
        else if (data?.members && Array.isArray(data.members)) members = data.members;
        else if (data?.familyGroup?.members && Array.isArray(data.familyGroup.members)) members = data.familyGroup.members;
        else if (data?.Members && Array.isArray(data.Members)) members = data.Members;

        // Return fallback if no members found
        if (!members || members.length === 0) return "Couldn't find";

        // Process members
        const memberList = members.map(m => {
            const u = m.user || m.profile || m.account || m; 
            
            // Get full name
            let fullName = "Unknown";
            if (u.displayName || u.DisplayName) {
                fullName = u.displayName || u.DisplayName;
            } else if ((u.firstName || u.FirstName) && (u.lastName || u.LastName)) {
                fullName = `${u.firstName || u.FirstName} ${u.lastName || u.LastName}`.trim();
            } else if (u.firstName || u.FirstName) {
                fullName = u.firstName || u.FirstName;
            } else if (typeof u.name === 'string') {
                fullName = u.name;
            } else if (u.name?.first && u.name?.last) {
                fullName = `${u.name.first} ${u.name.last}`;
            } else if (u.name?.first) {
                fullName = u.name.first;
            }

            // Get role
            let rawRole = m.memberRole || m.MemberRole || m.role || m.Role || m.familyRole || m.FamilyRole;
            let relation = "Unknown Role";

            // Convert numeric roles to strings
            if (rawRole == 1) {
                relation = "Organizer";
            } else if (rawRole == 2) {
                relation = "Member";
            } else if (rawRole !== undefined && typeof rawRole === 'string') {
                relation = rawRole;
            } else if (m.isChild !== undefined) {
                relation = m.isChild ? "Child" : "Organizer"; 
            } else if (m.isAdult !== undefined) {
                relation = m.isAdult ? "Organizer" : "Child";
            }

            return `${fullName} [${relation}]`;
        });

        // Return formatted result
        return `Total members: ${members.length}\nMembers:\n${memberList.join("\n")}`;
        
    } catch (error) {
        // Log error and fallback
        console.error("[-] [GET_FAMILY] Error:", error.response ? error.response.status : error.message);
        return "Couldn't find"; 
    }
};
