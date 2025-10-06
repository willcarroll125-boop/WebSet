// 1. Missing integrity checks
<script src="https://cdn.example.com/lib.js"></script> // No SRI
// 2. Unsafe deserialization
const userData = JSON.parse(untrustedInput);
eval(`(${serializedObject})`);
// 3. Untrusted plugin loading
const plugin = require(userProvidedPluginName);
// 4. Dynamic script loading
const script = document.createElement('script');
script.src = userProvidedURL;
document.head.appendChild(script);

