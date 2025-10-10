Recs = {
    "SQL Injection": """
<b>To address Injection vulnerabilities</b>, developers must implement proper input validation, output encoding, and use parameterized queries and safe APIs that prevent injection attacks.<br/><br/>
•  <b>Use Parameterised Queries / Prepared Statements:</b> Always use parameterised queries or prepared statements. Avoid concatenating SQL strings with user input.<br/>
• <b>Implement Output Encoding:</b> Sanitise and encode all inputs before processing.<br/>
•  <b>Avoid Dangerous Functions:</b> Never use <code>eval()</code>, <code>Function()</code>, or <code>setTimeout()</code>/<code>setInterval()</code> with string arguments containing user input.<br/>
• <b>Use Safe DOM Manipulation Methods:</b> Prefer <code>insertAdjacentHTML()</code> instead of <code>innerHTML</code>/<code>outerHTML</code>. Consider DOMPurify when rendering HTML.<br/>
• <b>Implement Input Validation:</b> Validate all user input on both client and server sides. Use whitelists and reject invalid inputs.
""",

    "Broken Access Control": """
<b>To address Broken Access Control</b>, enforce authorisation on the server and apply deny-by-default logic.<br/><br/>
• <b>Implement Server-Side Access Control:</b> All checks must be enforced server-side.<br/>
• <b>Centralise Access Control:</b> Keep authorisation in a single auditable component.<br/>
• <b>Replace Direct Object References:</b> Use indirect IDs and verify permissions per resource.<br/>
• <b>Secure API and Endpoint Access:</b> Validate roles/permissions for every request.<br/>
• <b>Remove Hardcoded Credentials:</b> Don’t ship keys/tokens in client code; use a secrets manager.
""",

    "Cryptographic Failures": """
<b>To address Cryptographic Failures</b>, developers should implement strong and modern encryption standards to ensure data confidentiality during transmission and storage.<br/><br/>
• <b>Secure in Transit - Strong Cryptographic Protocols:</b> Always use HTTPS with strong TLS configurations to encrypt data in transit with secure cipher suites.<br/>
• <b>Use Standardised and Secure Modern Cryptographic Algorithms:</b> Ensure use of algorithms such as AES-256 for symmetric encryption and SHA-256 or SHA-512 for hashing. Never use outdated or weak algorithms like MD5, SHA1, or DES.<br/>
• <b>Securely Store Sensitive Data:</b> Never store passwords, credit card numbers, or personal identifiers in plain text or local storage. Use secure cookies and encrypt sensitive data at rest using strong encryption algorithms.<br/>
• <b>Implement Proper Key Management:</b> Never hardcode encryption keys, salts, or secrets in code. Use secure key storage solutions and rotate keys regularly.<br/>
• <b>Use Cryptographically Secure Random Generators:</b> Replace <code>Math.random()</code> with cryptographically secure generators for tokens or session IDs.<br/>
• <b>Implement Proper Password Hashing:</b> Use purpose-built hashing algorithms like <code>bcrypt</code>, <code>scrypt</code>, or <code>Argon2</code> with unique salts for each password.<br/>
""",

    "Insecure Design": """
<b>To address Insecure Design</b>, developers must integrate security into the design phase through secure design principles, threat modelling, and proactive risk assessment.<br/><br/>
• <b>Implement Rate Limiting and Throttling:</b> Apply rate limiting to critical operations such as login, password reset, or payment processing. Consider exponential backoff or CAPTCHA for repeated failed attempts.<br/>
• <b>Apply Defence in Depth:</b> Layer multiple levels of security controls, including input validation, authentication, and encryption.<br/>
• <b>Implement Comprehensive Input Validation:</b> Enforce rules that validate ranges, formats, and limits for all user inputs, ensuring consistency with business logic.<br/>
• <b>Implement Secure Error Handling:</b> Display generic error messages to users and log detailed errors securely on the server side.<br/>
• <b>Apply Principle of Least Privilege:</b> Give users only the permissions necessary for their tasks. Regularly review and audit permissions.<br/>
""",

    "Security Misconfiguration": """
<b>To address Security Misconfiguration</b>, developers should maintain secure defaults, disable unnecessary features, and ensure consistent configuration across environments.<br/><br/>
• <b>Disable Debug Mode in Production:</b> Remove or disable all debugging, logging, or developer features before deployment.<br/>
• <b>Remove Development Artifacts:</b> Clean up unnecessary code, comments, temp files, or unused dependencies before release.<br/>
• <b>Implement Security Headers:</b> Configure comprehensive security headers such as CSP, X-Frame-Options, and Strict-Transport-Security for all web responses.<br/>
• <b>Use Secure Defaults:</b> Change default credentials, passwords, and API keys before deployment. Disable unused default accounts.<br/>
• <b>Minimise Attack Surface:</b> Disable unneeded services, ports, and features. Remove unused dependencies or libraries.<br/>
• <b>Secure Configuration Management:</b> Store configurations securely using secrets management systems. Avoid committing sensitive configs to version control.<br/>
• <b>Regular Security Updates:</b> Patch and update dependencies and frameworks regularly to mitigate known vulnerabilities.<br/>
• <b>Configuration Auditing:</b> Regularly audit configurations against security benchmarks and automate scans for deviations.<br/>
""",

    "Identity and Authentication Failures": """
<b>To safeguard against Identity and Authentication Failures</b>, enforce robust password, session, and authentication management aligned with industry standards.<br/><br/>
• <b>Enforce Strong Password Policies:</b> Require passwords of at least 12 characters with uppercase, lowercase, numbers, and symbols. Enforce account lockout after repeated failed attempts and check against breached password lists.<br/>
• <b>Secure Session Management:</b> Use unpredictable, cryptographically secure session IDs and invalidate sessions on logout, idle timeout, or privilege change.<br/>
• <b>Avoid Hardcoded Credentials and Secrets:</b> Never store credentials or API keys in source code. Use environment variables or secret management tools like AWS Secrets Manager or HashiCorp Vault.<br/>
• <b>Implement Multi-Factor Authentication (MFA):</b> Require MFA for all sensitive or privileged accounts. Prefer TOTP-based or hardware key methods over SMS.<br/>
• <b>Implement Single Sign-On (SSO):</b> Use SSO via modern authentication protocols (e.g., OAuth2, SAML) to reduce credential fatigue and improve access control.<br/>
""",

    "Software and Data Integrity Failures": """
<b>To prevent Software and Data Integrity Failures</b>, enforce verification and integrity controls for external and internal code dependencies.<br/><br/>
• <b>Restrict External Resource Usage:</b> Only use pre-approved, trusted domains for scripts, stylesheets, and other external resources. Host critical assets internally wherever possible.<br/>
• <b>Maintain Dependency Hygiene:</b> Keep all third-party libraries updated and monitor them for known vulnerabilities using tools like OWASP Dependency-Check, npm audit, or Snyk.<br/>
• <b>Enforce Subresource Integrity (SRI):</b> Require external scripts and stylesheets to include cryptographic integrity attributes (e.g., <code>sha384</code>) so browsers can verify authenticity before execution.<br/>
""",

    "Vulnerable/Outdated Components":"""
    
""",
"Server-Side Request Forgery":"""

""",



}
