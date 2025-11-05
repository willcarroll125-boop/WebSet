Recs = {
    "Injection": """
<b>To address Injection vulnerabilities, developers must implement proper input validation, output encoding, and use parameterized queries and safe APIs that prevent injection attacks.</b><br/><br/>
• <b>Use Parameterised Queries/Prepared Statements:</b> Always use parameterised queries or prepared statements when connecting databases. Avoid constructing SQL queries using string concatenation with any user input.<br/>
• <b>Implement Output Encoding:</b> Sanitise and encode all inputs before processing.<br/>
• <b>Avoid Dangerous Functions:</b> Never use <code>eval()</code>, <code>Function()</code> constructor, or <code>setTimeout()/setInterval()</code> with string arguments containing user input.<br/>
• <b>Use Safe DOM Manipulation Methods:</b> Use safe methods to replace <code>innerHTML</code>, <code>outerHTML</code>, or <code>insertAdjacentHTML()</code>. When HTML rendering is necessary, consider sanitisation libraries such as DOMPurify.<br/>
• <b>Implement Input Validation:</b> Validate all user input on both client and server-side. Configure whitelists of acceptable input patterns and reject invalid inputs.<br/>
""",

    "Broken Access Control": """
<b>To address Broken Access Control, developers must implement server-side authorisation as client-side checks are easily bypassed. Prioritise the following recommendations:</b><br/><br/>
• <b>Implement Server-Side Access Control:</b> All access control decisions must be enforced from the server. The client should only display what is authorised by the server. Apply Zero-trust methodology and implement <i>deny-by-default</i> logic.<br/>
• <b>Centralise Access Control:</b> Consolidate authorisation processes and logic into a centralised component. This improves visibility and ease to manage and audit permissions across the web application.<br/>
• <b>Replace Direct Object References:</b> Instead, prioritise use of <i>indirect object references</i> instead of hardcoded, sequential or predictable IDs in URLs and parameters. These IDs can be mapped to the actual database IDs on the server-side, and validate user permissions to access the requested resource.<br/>
• <b>Secure API and Endpoint Access:</b> Every API endpoint should check a user's role and permissions before processing a request. Don't trust any data sent from the client regarding user roles or privileges.<br/>
• <b>Remove Hardcoded Credentials:</b> Never hardcode credentials, API keys, or tokens in client-side code (JavaScript, HTML). Store them securely in environment variables or a secrets management system on the server.<br/>
""",

    "Cryptographic Failures": """
<b>To address Cryptographic Failures, developers should endeavor to implement strong encryption algorithms up to modern standards, ensuring data is encrypted during transit and at rest.</b><br/><br/>
• <b>Secure in Transit - Strong Cryptographic Protocols:</b> Always use HTTPS with strong TLS configuration to encrypt data in transit with modern, secure ciphers.<br/>
• <b>Use Standardised and Secure Modern Cryptographic Algorithms:</b> Ensure use of algorithms such as AES-256 for symmetric encryption and SHA-256 or SHA-512 for hashing. Never use outdated or weak algorithms like MD5, SHA1, or DES.<br/>
• <b>Securely Store Sensitive Data:</b> Never store sensitive data like passwords, credit card numbers, or PII in local or session Storage. Use secure cookies for session tokens. Encrypt sensitive data at rest using stronger encryption algorithms.<br/>
• <b>Implement Proper Key Management:</b> Never hardcode encryption keys, salts, or secrets in code. Invest in secure key management or restricted access. Regularly rotate keys and use unique keys often.<br/>
• <b>Use Cryptographically Secure Random Generators:</b> Replace <code>Math.random()</code> with cryptographically secure alternatives for generating tokens, session IDs, or any security related random values.<br/>
• <b>Implement Proper Password Hashing:</b> Never use general-purpose hash functions such as MD5, SHA-256 for passwords. Instead use purpose-built password hashing algorithms such as <code>bcrypt</code>, <code>scrypt</code>, or Argon2. Always use unique salts for each password.<br/>
""",

    "Insecure Design": """
<b>To address Insecure Design, developers must integrate security into the design phase of application development, implementing threat modeling and secure design patterns from the outset.</b><br/><br/>
• <b>Implement Rate Limiting and Throttling:</b> Add rate limiting to critical or sensitive operations such as login, password reset, payment processing, and API calls. Consider exponential backoff for repeated failed attempts or implementing CAPTCHA for suspicious activity.<br/>
• <b>Apply Defense in Depth:</b> Establish multiple layers of security controls such as input validation, authentication, authorisation, and encryption.<br/>
• <b>Implement Comprehensive Input Validation:</b> Design validation rules that enforce business logic constraints such as minimum values, ranges, formats, decimals, limits.<br/>
• <b>Implement Secure Error Handling:</b> Use generic error messages when displaying to users whilst logging detailed errors securely on the server side.<br/>
• <b>Apply Principle of Least Privilege:</b> Enforce only the minimum permissions necessary to perform their functions. Regularly conduct reviews and audit permissions.<br/>
""",

    "Security Misconfiguration": """
<b>To address Security Misconfiguration, developers must establish secure defaults, disable unnecessary features, and maintain consistent hardening across all environments.</b><br/><br/>
• <b>Disable Debug Mode in Production:</b> Remove or disable all debug flags, text output logging, and development features before public deployment.<br/>
• <b>Remove Development Artifacts:</b> Clean code of unnecessary code and comments, debugging, temp or unused libraries and dependencies, developer tools and scripts etc.<br/>
• <b>Implement Security Headers:</b> Configure and ensure use of comprehensive security headers for securing communications.<br/>
• <b>Use Secure Defaults:</b> Change all the pre–set default credentials, passwords, and API keys before deployment. Disable any default accounts.<br/>
• <b>Minimise Attack Surface:</b> Disable all unnecessary features, services, ports, and endpoints. Remove any unused dependencies or libraries.<br/>
• <b>Secure Configuration Management:</b> Store configs securely using secret management systems. Never publish sensitive configuration to version control. Use different configurations and credentials for development, staging, and production.<br/>
• <b>Regular Security Updates:</b> Establish processes for regularly updating and patching application components and dependencies.<br/>
• <b>Configuration Auditing:</b> Regularly audit configs against benchmarks and baselines. Invest in automated configuration scanning tools to detect vulnerabilities or gaps.<br/>
""",

    "Identity and Authentication Failures": """
<b>To safeguard your web application against Identity and Authentication Failures, migrate key password validation mechanisms to server-side validation, and implement password policies in alignment with established industry standards such as the NIST Framework.</b> Additionally consider:<br/><br/>
• <b>Enforce Strong Password Policies:</b> Require passwords to meet complexity requirements extracted from known frameworks such as NIS, which mandates a minimum requirement of 12 characters, a mix of upper/lowercase letters, numbers, symbols, etc. Enforce account lockout after repeated failed login attempts and provide password strength feedback at creation. Integrate checks against known breached password lists using services like HaveIBeenPwned.<br/>
• <b>Secure Session Management:</b> Ensure session IDs comply with pseudorandom principles to remain unpredictable, securely generated (e.g., using cryptographically secure random number generators), and transmitted only over encrypted HTTPS traffic. In addition, Invalidate sessions on logout, idle timeout, and password change, and only store session tokens securely using technologies such as HTTP-only, Secure, and SameSite cookies and regenerate tokens after privilege escalation or login.<br/>
• <b>Avoid Hardcoded Credentials and Secrets:</b> Do not store passwords, API keys, or secrets in source code, configuration files, or front-end assets, and any other forms of plaintext storage. Instead, use environment variables or a dedicated secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager) and rotate them regularly.<br/>
• <b>Implement Multi-Factor Authentication (MFA):</b> Support MFA for all accounts, especially for administrative and high-privilege users. Prefer TOTP-based apps (e.g., Google Authenticator) or hardware security keys (e.g., YubiKey) over SMS-based methods, which are susceptible to interception.<br/>
• <b>Implement Single Sign On (SSO):</b> Use SSO through modern authentication protocols such as OAuth2, OpenID Connect, SAML, etc. to manage authentication where possible. This reduces the attack surface and simplifies identity management across distributed applications.<br/>
""",

    "Software and Data Integrity Failures": """
<b>To safeguard your web application against the use of unverified or malicious files, enforce strong controls around the loading, usage, and verification of external resources such as JavaScript libraries, stylesheets, and other remote assets.</b> These files, if tampered with or sourced from untrusted locations, may lead to injection attacks or unauthorised code execution in the client’s browser. Additionally consider:<br/><br/>
• <b>Restrict External Resource Usage:</b> Restrict the use of third-party scripts, stylesheets, and other resources to pre-approved, trusted domains through well-defined allowlists. Consider the authenticity of CDNs and any external sources prior to their inclusion in your application. Wherever possible, internally host critical resources to reduce dependency on external infrastructure and mitigate the risk of content injection or supply chain compromise. Monitor all externally sourced content for changes and enforce automated controls in CI/CD pipelines to detect unauthorized updates.<br/>
• <b>Maintain Dependency Hygiene:</b> Keep all third-party libraries and packages up to date, and monitor them continuously for known vulnerabilities using software composition analysis tools. Integrate dependency checks into your build process using tools such as OWASP Dependency-Check, npm audit, or Snyk to ensure visibility into package risk.<br/>
• <b>Enforce Subresource Integrity (SRI):</b> Require all externally loaded scripts and stylesheets to include cryptographic integrity attributes that validate the authenticity of the resource before it is executed by the browser. Subresource Integrity ensures that even if a third-party server is compromised, the browser will reject any modified or malicious file whose hash does not match the expected value. Only use trusted cryptographic algorithms (e.g., SHA-384), and ensure integrity attributes are updated as part of the release process when resources are changed.<br/>
""",

    "Vulnerable/Outdated Components":"""
<b>To mitigate the risk associated with A06, it is imperative for organisations to implement a strong version management and dependency hygiene policy, that prioritises a robust third-party component management.</b> These components comprise a range of libraries, frameworks, cloud SDKs, and plugins, which must be patched and updated in to ensure compliance with known industry standards and government regulations, and will inevitably curb the prospect of an attacker yielding A06 from your code. Additionally, you may also account for the following to further protect your code against exploits:<br/><br/>
• <b>Inventory of Components:</b> Maintain an up-to-date inventory of all third-party components used in the application including their version numbers, origin/source, and license type. This includes both frontend and backend packages, where tools such as Software Composition Analysis (SCA) may assist in automating the detection process. Alternatively, Azure offers its Application Insights service, which indeed comprises a similar element.<br/>
• <b>Use Trusted Sources and Package Registries:</b> Always install packages and updates from official or trusted repositories (e.g., npm, PyPI, Maven Central). Avoid using packages from unknown developers or copied from unofficial mirrors or GitHub repos without a vetting process.<br/>
• <b>Update Dependencies Frequently:</b> Set up an automated process to check for updates to all packages (including transitive dependencies) at least weekly. Use tools like Dependabot, Renovate, or Snyk to get automatic pull requests for security fixes and version bumps.<br/>
""",
"Server-Side Request Forgery":"""
<b>To defend your web application against SSRF, the primary control that must be implemented comprises the restriction of how and where user input can influence backend network requests.</b> Additionally, the following strategies may further assist in this:<br/><br/>
• <b>Strictly Validate and Whitelist URLs:</b> Never allow raw user input to be passed directly into request functions, where in lieu, you maintain an explicit allowlist of domains or IPs your app is allowed to contact backend servers. Imperatively, ensure that URLs are parsed properly and checked for disallowed patterns, including local IPs (127.0.0.1, 169.254.x.x, etc.), localhost, and encoded tricks like 0x7f000001.<br/>
• <b>Block Access to Internal and Metadata Addresses:</b> Ensure that requests cannot reach internal networks or cloud metadata services like AWS IMDS. Implement DNS resolution and IP filtering to block private or link-local ranges (10.0.0.0/8, 192.168.x.x, 169.254.x.x). Use cloud features like IMDSv2 and disable metadata access where not required.<br/>
• <b>Avoid Following Redirects Blindly:</b> Do not follow redirects from user-supplied URLs unless each redirect target is revalidated against your allowlist, to eliminate the primary threat vector of SSRP which operates through redirect chains.<br/>
• <b>Log and Monitor Suspicious Outbound Requests:</b> Log all server-side HTTP requests that are triggered by user input, and utilise SIEMs to monitor for unusual destinations, internal IPs, or metadata service access attempts. Particularly, use anomaly detection or rate-limiting to reduce exploitation attempts.<br/>
""",
"Security logging and Monitoring Failures":"""
<b>Remediation for A09 predominantly places an emphasis on the logging of critical security events, which must also be monitored through tools such as Security Information and Event Management (SIEM) to detect and respond to threats in a timely manner. However, the data to be logged must also account for the following considerations to curb any risk associated with the logging system itself:</b><br/><br/>
• <b>Log Security-Relevant Events Consistently:</b> Always log important events such as failed logins, access to sensitive endpoints, permission changes, and unexpected errors, in alignment with the who did what, when, and from where framework.<br/>
• <b>Avoid Logging Sensitive Information:</b> Never log sensitive data such as passwords, API keys, tokens, or personal information. Always sanitise logs to prevent accidental data leaks or compliance violations.<br/>
• <b>Implement Real-Time Alerting for Suspicious Activities:</b> Set up automated alerts for anomalies like repeated login failures, unusual access patterns, or privilege escalations, and ensure that they are routed to Security Analysts.<br/>
• <b>Centralise and Secure Log Storage:</b> Use a centralised, tamper-resistant logging system to collect and store logs across services in alignment with log immutability standards. Additionally adjust log retention to allow for effective post-incident forensics, and also ensure compliance with industry standards and government regulations.<br/>
""",


}
