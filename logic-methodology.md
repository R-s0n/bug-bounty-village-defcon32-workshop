# My Full Bug Bounty Hunting Methodology - Logic

*GOAL: Send Unexpected HTTP Requests (Or a Series of Requests) to Cause the Application to Act in an Unexpected Way*

When hunting for logic vulnerabilities, your goal as the attacker is to send an HTTP Request (or sequence of requests) that the developers did not plan for.  Maybe they forgot to apply an Access Control to a specific endpoint/mechanism.  Or maybe they failed to validate that a client *should* be able to access a larger data set from a single unique identifier.  Maybe if you drop an request or two in a complex sequence, the mechanism fails open?  All of these are possibilities.  If you understand how an application works at a deep level and learn to identify insecure patterns, you can start to "bend" the logic of the application to cause unexpected behavior without actually breaking the app.

- Core Steps:
    - Understand the Application on a Deep Level
    - Identify Complex & Critical Mechanisms
    - Send Unexpected Sequence of Events or Requests


# Learn The App

The best programs to do logic testing on are Software-as-a-Service (SaaS) companies that have large, complex web applications.  The application must have authentication and should have complex access controls, a wide range of mechanisms/functionality, and designed to be used by a large number of users simulatenously.  Unlike injection testing where you can isolate specific attack vectors, logic testing requires requires the bug bounty hunter to see the "bigger picture" of how the different components of an application work together.  You must first understand how the app works so you can identify the cracks and try to bend/break the logic.  *Before I begin logic testing a target application, I spend at least 2-3 days understanding how the application works before I do ANY testing.*  Your mindset should be that you have been hired by this company and are now part of their application security team.  

## Architecture

- *What language is the back-end written in?* - Each server-side language has unique properties that effect the way a bug bounty hunter will approach it.  This is especially true for injection testing, but there are several ways the server-side language can effect how the logic of an application executes.  Here are a few examples:
    - [PHP $_SESSION vs $_COOKIE](https://www.geeksforgeeks.org/what-are-the-difference-between-session-and-cookies-in-php/) - The handlers PHP uses to access a session token vs. a cookie work in *almost* the same how, with the main difference being session tokens are stored on the server-side while cookies are stored in the client's browser and can be controlled by an attacker.  Imagine a scenario where a new PHP developer intended to set a session token with the user's ID value stored in it.  The code should look like this: `<?php session_start(); $_SESSION['user_id'] = 1; echo "Thank you for logging in!  Your user ID is: " . $_SESSION['user_id']; ?>`  However, if the developer accidently used a cookie instead, the user can easily modify the user ID value in the cookie and access another user's data: `<?php setcookie('user_id', 1, time() + (86400 * 30));  ; echo "Thank you for logging in!`
    - [PHP/Node Loose Comparison](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Equality_comparisons_and_sameness) - [Strict Typing Languages](https://en.wikipedia.org/wiki/Strong_and_weak_typing) like Java and C# don't need different comparison operations because the type is already known.  For less strict typing languages like PHP and JavaScript, though, there are two different methods to compare variables.  The `==` operator compares the value of the variables without considering the type.  This means all positive `int` values equal `true`, `"1"` equals `1`, etc.  However, the `===` operator also compares the type of each variable, so `"1" === 1` would return `false`.  Now consider how this can effect the mechanisms of an application.  If a `==` operator is being used to compare a password, can you submit a `true` boolean to force the login mechanism to fail open?  Anywhere that user-controlled input is compared to a value in stored on the server-side, for PHP or Node applications, there is the possibility of a loose comparison.  [Java has a similar situation with `==` vs. `.equals()`](https://www.geeksforgeeks.org/difference-between-and-equals-method-in-java/), but with different implications.
- *Is the app using a frontend framework? (React, Angular, NextJS, etc.)* - Each of the well-known JavaScript frontend frameworks have their own way of rendering a DOM.  React builds a virtual DOM in the client's browser while NextJS renders the DOM on the server-side, encodes it, then decodes and renders it again in the client's browser.  These frameworks can have an especially big impact on how Access Controls are implemented.  If someone is using React Router, for example, then the access controls are implemented on the client-side.  This is very different from how [NextJS](https://nextjs.org/docs/pages/building-your-application/routing) handles routing.  If you're lucky enough to find an application with React on the frontend that has not properly obfuscated the webpack **and** is using React Router, you can easily download the raw source code and see exactly how the access controls are implemented.  This saves a *ton* of time testing granular access controls.
- *What additional client-side NPM Packages are used?* - Almost all applications you will target as a bug bounty hunter will have [NPM Packages](https://www.npmjs.com/) on the client-side as API's to facilitate actions throughout the app.  These packages will contain JavaScript [methods](https://www.geeksforgeeks.org/difference-between-methods-and-functions-in-javascript/) that the developers can use to perform complex operations in the client's browser.  Many NPM packages have known vulnerabilities which you can look up on webpages like [Snyk](https://snyk.io/advisor/npm-package/npm).  Keep in mind that just having a package of the vulnerable version does not mean the application is vulnerable.  The developers also need to use the vulnerable *method* as well, but don't just consider if the package has vulnerabilities.  Instead, consider how the package works and what problems it solves.  This can help inform your logic testing.  If you see [lodash](https://snyk.io/advisor/npm-package/lodash) used, don't just test for [Prototype Pollution](https://security.snyk.io/vuln/SNYK-JS-LODASH-6139239) and move on.  Lodash is often used to merge objects, so maybe you can find a way to inject unexpected values into a critical JSON object?  That's just one idea...
- *Does the app have any custom client-side JavaScript files?* - The client-side code in NPM packages is available for any security researcher that would like to test for vulnerabilities.  This means using an NPM package can have both a positive and negative effect on your application's security posture.  On the positive side, the code has been thoroughly tested so you can be confident the latest version of the package is secure.  However, if you are not using the latest version of the package, attackers can easily identify this and try to exploit known vulnerabilities.  With custom JavaScript, the benefits and drawbacks are exactly the opposite.  Custom client-side JavaScript has only been tested by the company's internal quality engineers and/or security team.  This means it will be harder to find vulnerabilities, but there is a much greater likelihood that you will be able to cause the code to act in a way the developer did not intend.  I *love* to test on applications with large amounts of custom JavaScript.  First, try to find flaws in the logic.  Check each conditional, for loop, etc.  Anywhere that variables containing user-controlled data are evaulated, especially if there is data related to the client's **Identify** or **Role**.  Keep in mind that most client-side JavaScript, even custom files, will be [minified](https://www.cloudflare.com/learning/performance/why-minify-javascript-code/).  Tools like [JSNice](http://jsnice.org/) can help make minified JavaScript readable.
- *Is there Authentication?* - In my opinion, authentication is a requirement for logic testing.  An application without authentication rarely has enough complexity to find impactful logic flaws.  With authentication, you open up the possibility for [Insecure Direct Object References (IDORs)](https://portswigger.net/web-security/access-control/idor) or [Access Control Violations](https://portswigger.net/web-security/access-control).  But it's important to remember that there are many different ways of allowing a user to authenticate.  Each of these authentication methods will have a downstream effect on how you will attack the application's logic.
    - Username/Password - This is the simplest form of authentication.  Behind the scenes, the application stores a unique String (Username) and the [hash value](https://nordpass.com/blog/password-hash/) of a unique String (Password).  When the application needs to prove the client's identity (checking for IDORs), it will either use the Username itself as the unique identifier, or it will use a user ID value as part of the larger User Object.  If the application does leverage the Username value as the unique identifier, then you can attempt to break the code pattern that validates the Username to gain access to another user's data.  For example, what happens if you register an account with the same Username as another user, but you're able to append a unique [ASCII Character](https://www.ascii-code.com/) like a [Null Byte](https://en.wikipedia.org/wiki/Null_character) to the end.  Will you be able to register a unique account (registration mechanism believes this is a unique String) *and* access data from the victim user (client's identity validation believes this is NOT a unique String)?  It's definitely worth a shot!
    - Email/Password - This auth pattern works very similar to the Username/Password pattern, with the added complexity of [the funky way email syntax works](https://datatracker.ietf.org/doc/html/rfc2822#section-3).  One of my favorite mechanisms to play with while testing this pattern is [Plus Addressing](https://eit.ces.ncsu.edu/2023/02/gmail-plus-addressing-the-hidden-feature-that-can-help-you-get-more-out-of-your-inbox/).  This allows you to create unique user accounts that are tied to the same email address.  This could have implications for password reset requets or any other mechanism that requires an email to be sent to the user's address. Email syntax can also make writing [regex](https://en.wikipedia.org/wiki/Regular_expression) to validate the username is much more complex because it's not just a string, it's a specific syntax pattern.  Aim for mechanisms that would require you to 
    - Single Sign On (SSO)
    - OAuth
- *What Objects can you enumerate?*
- *How is session established?*
    - Cookie Unique String
    - Cookie Storing Data No Signature
    - Cookie Storing Data Signature
    - JSON Web Token (JWT)
    - localStorage
- *What type of Access Controls are implemeneted?*
    - Role-Based Access Controls (RBAC)
    - Discretionary Access Controls (DAC)
    - Policy-Based Access Controls (PBAC)
- *Is there an API?*
    - API First Model?
    - Internal or External?
    - API Key or Session Token?
    - Documentation
- *Is CORS implemented?*
- *Is Captcha used?*
- *Is Rate Limiting Implemented?*
- *Are WebSockets used?*
- *Are They Using a Content Delivery Network (CDN)?*

## Security Controls

- Is there client-side validation on user-controlled input?
- How does the application handle user-controlled input on the server-side?
    - Does it validate the **type** of the user-controlled input?
    - Does it validate the **size** of the user-controlled input?
    - Does it sanitize for potentially malicious characters?
- Is there a Web Application Firewall (WAF)?
- Is there a Content Security Policy?
- How is user-controlled input rendered/encoded in the DOM?

## Best Practices

- Are there useful comments?
- Can you trigger any error messages?
- Is the source code publicly available?

# Enumerate The Mechanisms

- 
- *Think Like QE! How Would You Build Test Scripts?*

## CREATE
- 

## READ
- 

## UPDATE
- 

## DELETE
- 

# Test The App

## Missing Security Controls

- Lack of Access Controls
- Lack of Rate Limiting

## Bypass Security Controls

- Bypass Access Controls
    - Unauthenticated -> Authenticated
    - RBAC Bypass
    - Granular Access Control Bypass
- Bypass Rate Limiting
- Bypass 2FA/MFA
- Bypass Payment Process Restrictions
- Bypass Captcha
- Bypass Registration Restrictions
- Bypass Password Reset Restrictions

## Insecure Direct Object Reference (IDOR)

- Does the endpoint return a unique response based on the client's identity?
- Does the endpoint identify the client by establishing a User Context via a Session Token?
- Does the endpoint identify the client through an ID value with a signature (JWT, etc.)
- Does the endpoint simply pull an ID value from a parameter?

## OAuth Testing

*SUMMARY: OAuth testing is one of my favorite ways to test for several reasons.  First, OAuth is fairly complex and there are hundreds of different ways to implement the protocol/framework (I've heard it called both).  First, as I've mentioned before, [OAuth was never designed to be used for Authentication](https://medium.com/@scottbrady91/oauth-is-not-user-authorization-1e85eff10344), so if you find an application using OAuth for authentication you've already found a major design flaw.  And don't even get me started on using [JSON Web Tokens (JWTs) for Session Tokens](https://developer.okta.com/blog/2017/08/17/why-jwts-suck-as-session-tokens).  Anyway, I digress...  OAuth can be implemented in many different patterns with optional variables based on the functionality the developers are looking for.  The fact that OAuth is so adaptable is great for flexibility, but it also can make implementing OAuth very complex.  As always, this complexity is where the vulnerabilities will live.  Also keep in mind that developers are just trying to complete the work they've been asigned on a ticket.  They are rarely considering how the OAuth patterns and configurations they choose effect the security of the mechanism.  If you understand how the many OAuth patterns work, you can easily identify which patterns have been used in an application.  From there, check for known dangerous patterns like not including a [state token](https://auth0.com/docs/secure/attack-protection/state-parameters) or [not validating the redirect_uri](https://www.oauth.com/oauth2-servers/redirect-uris/redirect-uri-validation/).  Masters of OAuth testing can recognize how the pattern and configuration have a downstream effect on the other mechanisms throughout the application.  For example, an OAuth integration that does not limit the scope of access for a client to a GDrive instance may allow a legitimate user to access data within the GDrive that they should not have access to, simply because the OAuth scopes are misconfigured.  Don't just stop at checking for known issues with OAuth implementations.  Really learn how the protocol works and, over time, you will begin to see major security holes that can pay off big!*

### Steps of OAuth

#### Authorization Code

1. Authorization Request

Common parameters: `redirect_uri`/`response_type`/`scope`/`state`
```
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com 
```
2. User Consent
3. Authorization Code Grant
    - Common parameters: code/state
    - Vulnerable to CSRF
```
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com 
```
4. Access Token Request
    - Common parameters: client_secret/grant_type/client_id/redirect_uri/code
```
POST /token HTTP/1.1
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8 
```
5. Access token grant
    - Server responds with Bearer Token
6. API call
    - Contains Authorization header w/ Bearer Token
7. Resource grant
    - Server responds with sensitive data


- Step 1: Search traffic for known OAuth parameters
    - `client_id`
    - `redirect_uri`
    - `response_type`
    - `state`
- Step 2: Send GET request to known OAuth Service Provider endopints
    - `/.well-known/oauth-authorization-server`
    - `/.well-known/openid-configuration`
- Step 3: Identify Grant Type (response_type parameter)
    - Authorization Code -- response_type=code
    - Implicit -- response_type=token (More common in SPAs and Desktop Apps)
- Step 4: Identify misconfigurations that can be abused
    - Implicit -- All data in POST request not validated when establishing session
    - Authorization Code -- No state parameter used -> CSRF (most impact when linking accounts)
    - Authorization Code / Implicit -- Steal code/token through redirect_uri
        - There are several redirect possibilities:
            1. Redirect to any domain
            2. Redirect to any subdomain
            3. Redirect to specific domains
            4. Redirect to one domain, all paths
            5. Redirect to one domain, specific paths
            6. Redirect to one domain, one path
            7. Redirect to whitelisted domains and/or paths based on Regex
                - 8a. Can add parameters
                - 8b. Can add specific parameters
                - 8c. Cannot add parameters
                - *Note: Try using parameter pollution, SSRF/CORS defense bypass techniques, localhost.evil-server.net, etc.*
        - Step 1: Send malicious url with poisoned redirect_uri parameter
        - Step 2: Read code/token in response
        - Step 3: Substitute stolen code/token when logging in
        - *Note: If redirect_uri parameter is sent with code/token, server is likely not vulnerable*
        - Steal parameter data from hash fragments:
```
<script>
    if (document.location.hash){
        console.log("Hash identified -- redirecting...");
        window.location = '/?'+document.location.hash.substr(1);
    } else {
        console.log("No hash identified in URL");
    }
</script>
```
- 
    - Upgrade scope to access protected resources (depends on grant type):
        - Authorization Code:
            - Step 1: Register a malicious application with the OAuth server
            - Step 2: Victim approves limited scope
            - Step 3: Malicious application sends POST request to /token with expanded scope
            - Result: If the OAuth server does not validate the scope with the original request, the access token returned will have an expanded authorization
        - Implicit:
            - Step 1: Steal access token
            - Step 2: Manually send access token with expanded scope
            - Result: If the OAuth server does not validate the scope with the original request, the access token returned will have an expanded authorization
    - Sign up with victim's email to get account takeover

### OpenID Connect w/ OAuth

- Uses JWT (id_token)
- Keys can be exposed on /.well-known/jwks.json
- Configuration can be exposed on /.well-known/openid-configuration
- Can be combined with normal OAuth grant Types
    EX: response_type=id_token token || response_type=id_token code

Step 1: Check for dynamic registration (is some form of authentication required, like a Bearer token?)
Step 2: Craft a malicious registration payload for SSRF

## Creative Testing