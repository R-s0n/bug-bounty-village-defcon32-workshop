# My Full Bug Bounty Hunting Methodology - Logic

*GOAL: HTTP Requests Sent In Specific Sequence Causes The Application To Act In An Unexpected Way*
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
- What Objects can you enumerate?
- How is session established?
- How is a user identified?
- Are there multiple user roles?
- Is there an API?
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