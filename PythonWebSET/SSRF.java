// 1. User-controlled URLs
function fetchUserData(url) {
return fetch(url); // No validation
}

// 2. Proxy functionality
function proxyRequest(targetUrl) {
return axios.get(targetUrl);
}

// 3. Image/resource loading
function loadImage(imageUrl) {
const img = new Image();
img.src = imageUrl; // Could be internal URL
}

// 4. Webhook functionality
function callWebhook(webhookUrl, data) {
return fetch(webhookUrl, {
method: 'POST'
,
body: JSON.stringify(data)
});
}
