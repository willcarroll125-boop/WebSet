// 1. Weak password validation
function isValidPassword(password) {
return password.length >= 4; // Too weak
}

// 2. Insecure session handling
localStorage.setItem('sessionToken'
, token); // Should use httpOnly cookies
sessionStorage.setItem('userAuth'
, authData);

// 3. Missing authentication checks
function sensitiveOperation() {

// No authentication check
return performOperation();
}

// 4. Password in client-side code
const passwordRegex = /^(?=.*[a-z]).{8,}$/; // Revealing password policy

// 5. Insecure token handling
const token = btoa(username + ":" + password); // Weak token generation