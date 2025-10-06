// 1. SQL Injection (client-side query building)
const query = `SELECT * FROM users WHERE id = ${userId}`;
const sql = "UPDATE users SET name = '" + userName + "'";

// 2. XSS - Direct DOM manipulation
document.getElementById('content').innerHTML = userInput;
element.outerHTML = `<div>${userInput}</div>`;
$('#result').html(userData);

// 3. eval() usage
eval(userInput);
Function(userCode)();
setTimeout(userInput, 1000);

// 4. Command injection patterns
exec(`ping ${userInput}`);
system(userCommand);

// 5. Template injection
template = `Hello ${userInput}`;