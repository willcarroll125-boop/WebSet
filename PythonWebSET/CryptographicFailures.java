// 1. Weak algorithms
const hash = CryptoJS.MD5(password);
const encrypted = CryptoJS.DES.encrypt(data, key);
btoa(password); // Base64 is not encryption

// 2. Hardcoded keys/salts
const encryptionKey = "mySecretKey123";
const salt = "fixedSalt";

// 3. Weak random generation
Math.random(); // For cryptographic purposes
Date.now(); // Predictable

// 4. Storing sensitive data in localStorage
localStorage.setItem('password', userPassword);
sessionStorage.setItem('creditCard', ccNumber);

// 5. Transmitting sensitive data without encryption
fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({password: pwd}) // Over HTTP
});
