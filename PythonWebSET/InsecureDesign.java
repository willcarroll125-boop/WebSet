// 1. No rate limiting on operations
function login(username, password) {
    // Direct login attempt without throttling
    return authenticateUser(username, password);
}

// 2. Insufficient validation
function processPayment(amount) {
    if (amount > 0) { // Missing upper limit, currency validation
        return chargeCard(amount);
    }
}

// 3. Mathematical logic flaws
function applyDiscount(originalPrice, discountPercent) {
    return originalPrice * (1 - discountPercent); // No validation on discount range
}

// 4. Missing security headers
// No CSP, HSTS, or other security headers implementation

// 5. Sensitive information disclosure in errors
catch (error) {
    console.log(error); // Exposing stack traces
    alert("Database error: " + error.message);
}