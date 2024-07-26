# My Full Bug Bounty Hunting Methodology - Injection

- *GOAL: Unexpected User-Controlled Input Causes The Application To Act In An Unexpected Way*
- Targets Flaws in the Application's **Code**
- How It Works (Example):
    - Client Sends HTTP Request (User-Controlled Input)
    - App Code Stores Part of The Request as Variable
    - App Fails to Sanitize the User-Controlled Input
    - User-Controlled Input is Passed to a Method in App Code
    - Application Behaves in a Way it Was Not Intended To Behave

## Client-Side Injections
- *GOAL: Attacker's user-controlled input forces the DOM to load in a way that the developers did not intend'*
- **Input**: Single Attack Vector w/ Possible Injection
- Injecting HTML
    1. Find Reflected User-Controlled Input
        - `rs0n` in GET parameter reflected in `<h1>Welcome rs0n!</h1>`
    2. Escalate to HTML Injection
        - `<b>rs0n</b>` in GET parameter reflected in `<h1>Welcome <b>rs0n!</b></h1>`
        - `rs0n` is bold in browser
    3. Escalate to JavaScript Execution
        - `</h1><script>alert(document.domain)</script>` executes an alert w/ `document.domain`
- Injecting JavaScript
    - Typical JavaScript Injection
    - Client-Side Prototype Pollution
    - PostMessage Vulnerabilities
- Injecting CSS
    - Find Reflected User-Controlled Input in CSS
    - Escalate to Inject CSS
    - Escalate to Inject External Resources Loaders
- Weaponizing HTML-Based Client-Side Injections:
    - Compensating Controls:
        - **Client-Side Validation** (*PREVENTS ATTACK*) - No effect on security but can show you what the developers are concered about.
        - **Server-Side Validation** (*PREVENTS ATTACK*) - Ensure user-controlled input is the expected *type* and *size* you expect, sanitize for malicious characters.
        - **Web Application Firewall (WAF)** (*PREVENTS ATTACK*) - Blocks HTTP requests based on a ruleset, identifies malicious code patterns.
        - **Output Encoding** (*PREVENTS ATTACK*) - Encodes user-controlled input as it is output to the DOM, preventing malicious code from executing
        - **Cookie Flags** (*MITIGATES IMPACT*) - Directives that tell the browser how a cookie can be handled and where it can be sent.
        - **Content Security Policy (CSP)** (*MITIGATES IMPACT*) - Directives that tell the browser where and how recourses can be loaded, scripts can execute, connections can be established, and much more.
    - Showing Impact:
        - Steal victim's cookie
        - Force victim to make an HTTP request
        - Steal DOM of restricted pages
- **Output**:
    - Application Behaves Unexpectedly
    - That Behavior Has a Negative Impact on Sensitive Customer Data
    - Explain Impact:
        - 

## Server-Side Injections
- *GOAL: Attacker's user-controlled input forces a server-side method to execute in a way the developers did not intend*
- **Input**: Single Attack Vector w/ Possible Injection
- Fuzzing For Server-Side Injections
    - Basic Methodology
        - Break the Application
        - Understand Why the Application Broke
        - Weaponize the Break
    - Identify Fuzzing Targets
        - Parameters
        - Cookies
        - Headers
        - Any user-controlled input that looks like it is processed by the application
        - Prioritize params, especially if they are reflected in the DOM
    - Fuzzing The Target
        - Send an unexpected type (Ex: App expects a `String`, send `null` or an `int`)
        - Send a large payload (Ex: 10,000 of the letter `A`)
        - [Send unexpected characters](https://github.com/0xacb/recollapse) (Ex: All possible ASCII characters in Unicode, Hex, and Double Hex)
        - Backslash Powered Scanner
    - Vulnerability Examples by Language
        - Command Injection
            - Node: `child_process.execSync()`
            - PHP: `exec()` OR `system()`
            - Python: `subprocess.run()`
            - Java: `Runtime.getRuntime().exec()`
        - Code Injection - *Eval is Evil*
            - Node: `eval()`
            - PHP: `eval()`
            - Python: `eval()`
            - Java: `ScriptEngineManager manager = new ScriptEngineManager(); ScriptEngine engine = manager.getEngineByName("js");  Object result = engine.eval();`
        - Server-Side Request Forgery (SSRF)
            - Node: `http.request()` OR `axios.get()` OR `const fetch = require('node-fetch'); fetch()`
            - PHP: [cURL Extension](https://www.php.net/manual/en/book.curl.php)
            - Python: `requests.get()`
            - Java: `URL url = new URL(USER_CONTROLLED_INPUT); HttpURLConnection con = (HttpURLConnection) url.openConnection(); con.setRequestMethod("GET");`
        - Server-Side Template Injection (SSTI)
            - [Node](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jade-nodejs): `var html = jade.render('USER_CONTROLLED_INPUT', merge(options, locals));`
            - [PHP](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#twig-php): `$output = $twig > render (USER_CONTROLLED_INPUT)`
            - [Python](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-python): `template.render(USER_CONTROLLED_INPUT)`
            - [Java](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#spring-framework-java): [Code Examples](https://www.baeldung.com/spring-template-engines)
        - [Server-Side Prototype Pollution (SSPP)](https://labs.withsecure.com/publications/prototype-pollution-primer-for-pentesters-and-programmers)
            - Node:
- **Output**:
    - Application Behaves Unexpectedly
    - That Behavior Has a Negative Impact on Sensitive Customer Data
    - Explain Impact:
        - 

## Database Injections
- *GOAL: Attacker's user-controlled input forces the application to make a database query the developers did not intend*
- **Input**: Single Attack Vector w/ Possible Injection
- 
- **Output**:
    - Application Behaves Unexpectedly
    - That Behavior Has a Negative Impact on Sensitive Customer Data
    - Explain Impact:
        - 