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
- *Does the app have any custom client-side JavaScript files?* - 
- *Is there Authentication?* - 
    - Username/Password
    - Email/Password
    - Single Sign On (SSO)
    - OAuth
- What Objects can you enumerate?
- How is session established?
- What type of Access Controls are implemeneted?
    - Role-Based Access Controls (RBAC)
    - Discretionary Access Controls (DAC)
    - Policy-Based Access Controls (PBAC)
- Is there an API?
    - Internal or External?
    - API Key or Session Token?
    - Documentation
- Is CORS implemented?
- Is Captcha used?
- Are WebSockets used?

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

## Race Conditions


## OAuth Testing


## Creative Testing