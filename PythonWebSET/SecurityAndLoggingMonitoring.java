// 1. Missing security logging
function login(username, password) {
if (authenticate(username, password)) {

// No logging of successful login
return true;
}

// No logging of failed attempt
return false;
}

// 2. Information disclosure in logs
console.log("Login failed for user:", username,"password:"
, password);
console.error("Database error:", fullError);

// 3. Missing monitoring for sensitive operations
function transferMoney(from, to, amount) {

// No logging of financial transaction
return process transfer(from, to, amount);
}

// 4. No rate limiting logs
function apiCall() {
// No tracking of API usage
}
