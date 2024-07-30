# My Full Bug Bounty Hunting Methodology - Logic

*GOAL: Send Unexpected HTTP Requests (Or a Series of Requests) to Cause the Application to Act in an Unexpected Way*

- When hunting for logic vulnerabilities, your goal as the attacker is to send an HTTP Request (or sequence of requests) that the developers did not plan for.  Maybe they forgot to apply an Access Control to a specific endpoint/mechanism.  Or maybe they failed to validate that a client *should* be able to access a larger data set from a single unique identifier.  Maybe if you drop an request or two in a complex sequence, the mechanism fails open?  All of these are possibilities.  If you understand how an application works at a deep level and learn to identify insecure patterns, you can start to "bend" the logic of the application to cause unexpected behavior without actually breaking the app.

Core Steps:
    - Understand the Application on a Deep Level
    - Identify Complex & Critical Mechanisms
    - Send Unexpected Sequence of Events or Requests

# Learn The App

## Architecture

- What language is the back-end written in?
- Is the app using a client-side library? (React, Angular, NextJS, etc.)
- What additional client-side libraries are used? 
- Does the app have any custom client-side JavaScript files?
- Is there Authentication?
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

- Is there a Web Application Firewall (WAF)?
- How does it handle special characters?
- Is there a Content Security Policy?

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


## Creative Testing