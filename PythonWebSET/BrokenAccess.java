// 1. Client-side only authorization
if (user.role === 'admin') {
    showAdminPanel();
}

// 2. Hardcoded API keys/tokens
const API_KEY = "sk-1234567890abcdef";
const authToken = "Bearer eyJ0eXAiOiJKV1QiLCJhbGc...";

// 3. Direct object references
fetch(`/api/users/${userId}/profile`);
window.location = `/admin/users/${id}/edit`;

// 4. Role-based logic in frontend
function canDeleteUser(currentUser, targetUser) {
    return currentUser.id === targetUser.id; // Missing admin check
}

// 5. Insecure parameter handling
const isAdmin = urlParams.get('admin') === 'true';

