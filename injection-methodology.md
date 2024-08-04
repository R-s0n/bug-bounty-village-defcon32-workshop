# My Full Bug Bounty Hunting Methodology - Injection

*GOAL: Unexpected User-Controlled Input Causes The Application To Act In An Unexpected Way*

Injection attacks occur when user-controlled input in an HTTP Request is processed by the application in some way that causes the application to act in a way the developers did not intend.  It's really as simple as that.  The application accesses a value from the HTTP Request, passes that value to a block of code in the app, and that specific user-controlled input causes the application to act differently.  This unexpected behavior could be that the application [throws an error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500), reaches a new part of a [conditional](https://www.geeksforgeeks.org/conditional-statements-in-programming/) statement or [try/catch](https://www.w3schools.com/java/java_try_catch.asp#:~:text=The%20try%20statement%20allows%20you,occurs%20in%20the%20try%20block.), or any other of the countless ways an application could behave unexpectedly.  

### Step 1: [Fuzzing](https://owasp.org/www-community/Fuzzing) For Unexpected Behavior

The first step to finding any type of injection vulnerability is to find a specific pattern of user-controlled input that causes the unexpected behavior.  That *specific pattern* causing the unexpected behavior is known as a [payload](https://www.scaler.com/topics/cyber-security/what-are-payloads/).  When you begin to test for injection vulnerabilities, your payloads will be very simple, sually just a single character or HTML element.  You'll start by sending HTTP Requests to endpoints as intended and recording the expected response.  This allows you to establish a baseline of what the application's expected behavior is.  Then, you will send your payloads one-by-one to various attack vectors within the HTTP Request, looking for variations in the response.  If the response is different from the baseline, you have found a place where user-controlled input causes the application to act in an unexpected way.  Here are a few examples:

Baseline: GET -> `/fetch?dest=safeapp.com` results in [200 Response](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/200) with the message `Done!`
Variation GET -> `/fetch?dest=safeapp.com@` results in a [500 Response](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500) with the message `ERROR: Site cannot be reached!`
Unexpected Behavior: The response code changes to represent an error has occured.

Baseline: GET -> `/search?q=rs0n` results in an empty JSON Object being returned, along with a 200 Response
Variation GET -> `/search?q=rs0n"` results in a 500 Response
Unexpected Behavior: The response code changes to represent an error has occured and nothing is returned.

Baseline: GET -> `/welcome?user=rs0n` results in `<h1>Welcome rs0n</h1>`
Variation: GET -> `/welcome?user=<b>rs0n</b>` results in `<h1>Welcome <b>rs0n</b></h1>`
Unexpected Behavior: DOM renders [Formatted Text](https://www.w3schools.com/html/html_formatting.asp) HTML elements the developer did not intend to render.

### Step 2: Finding WHERE the Break is Occurring

This is exactly how [Dynamic Application Security Testing (DAST)](https://owasp.org/www-project-devsecops-guideline/latest/02b-Dynamic-Application-Security-Testing) scanners work.  With each of our examples, we have found a way to cause the application to behave in a way the developers did not intend (yes, I'm going to keep saying this).  Now we need to understand WHY the application is behaving differently, and the first step to doing that is to determine **what part of the application is processing the user-controlled input and behaving differently**.  There are three places where injection payloads could be executing: The Client-Side Code, the Server-Side Code, and the Database.  Where an injection is taking place has a *huge* impact on just about every aspect of the attack.  It effects what attacks are possible, what payloads could cause the initial unexpected behavior, how an attack is weaponized after it's successful, and much more.  So, let's look at each of our examples above and determine where the unexpected behavior is coming from:

- Sending a GET request to `/fetch?dest=safeapp.com@` causes the server to return a 500 Response instead of a 200.  This means something on the server-side is breaking before a DOM is returned, so we know the break is not happening on the client-side.  It must be either the server-side code or the database.  Since the unexpected behavior is caused by adding an `@` to the value of the parameter, we can look at the syntax of different databases to see if this character has a specific impact.  After doing that, we don't find any database that uses an `@` symbol as a critical operator, so we can make an educated guess that this is a server-side injection, keeping in mind it MAY be a rare database injection.

- Sending a GET request to `/search?q=rs0n"` also causes a 500 Response instead of the baseline 200 Response and an empty JSON object in the body.  Once again, we can rule out client-side injections because the break is happening before the DOM is being returned.  The name of the endpoint is `search` and the parameter name `q` is commonly used for search features.  The break is also caused by a `"` which is often used as part of many database queries.  Given this information, we can make an educated guess that this injection is occuring in the database query itself.

- Sending a GET request to `/welcome?user=<b>rs0n</b>` results in `rs0n` rendering in the DOM as bold font, which was not part of the original DOM.  Whenever user-controlled input is reflected in the DOM and the payload in that input causes new elements to be rendered in the DOM, that is a clear client-side code injection.

### Finding WHY the Break is Occuring

Now that we believe we know where each of these injections are occuring, we need to understand WHY the specific payload is causing unexpected behavior.  Why is this *specific* input causing this *specific* behavior.  We have broken the application in some way.  In order to weaponize the break, we need to figure out what is actually breaking so we know what capabilities we may have.

- Server-Side Injection | `/fetch?dest=safeapp.com@`
    - Why does the @ symbol cause the application to break here?  We can see that the value is a domain, let's do some research to see how the @ symbol is used in domains.
    - After some searching, we discover that the `@` symbol is [not allowed in domains](https://domainname.shop/faq?section=1&id=7&currency=USD&lang=en), so it's possible that is causing the break...but why?  It's not like the application is registering the domain every time you send a request, is it?
    - Given the name of the endpoint and error message, the most logical guess here is that the domain is being converted to a [URL](https://domainname.shop/faq?section=1&id=7&currency=USD&lang=en) and the server-side code is making an HTTP Request, but why would the `@` symbol break that?
    - After doing some research, we find that adding a `@` symbol after the domain in a URL will cause the browser to process the values *before* the `@` as a username and password, separated by a `:`
    - So, it seems that when `/fetch?dest=safeapp.com` is sent to the server, the value of the `dest` parameter is converted to a URL and passed to a server-side method that makes an HTTP request to that domain.  Adding the `@` to the end causes the URL to look like this: `https://safeapp.com@`.  When that URL is passed to a methodl like [node-fetch](https://www.npmjs.com/package/node-fetch), the invalid URL causes the server-side code to break and the error response to be sent.

- Database Injection | `/search?q=rs0n"`
    - We don't know what database the application is using, but we know that the `"` is causing the break.  Let's look up what databases use `"` as part of their queries...
    - After doing some research, it looks like most databases use `"` in some capacity, but SQL Queries specifically use double quotes as part of almost every query.  NoSQL databases require the use of a `$` operator to make queries and `"` are only used for strings.  Based on this information, I believe we can assume it is a [SQL Database](https://www.w3schools.com/sql/sql_intro.asp).
    - Assuming it is a SQL Database, the value of the q parameter is likely being appended directly to the SQL Query, changing `SELECT * FROM main_table WHERE data CONTAINS "rs0n";` to `SELECT * FROM main_table WHERE data CONTAINS "rs0n"";` resulting in an invalid SQL Query and an error being returned.

- Client-Side Injection | `/welcome?user=<b>rs0n</b>`
    - With this example, we haven't actually broken the app, but we caused it to render a DOM that is different from what the developers intended.  There are a few different ways this can happen, but the main question we need to answer is whether the DOM is being built on the server-side and returned in the response or if the DOM is built on the client-side using JavaScript.  This will effect how we approach weaponizing this behavior.  Testing this is easy, simply search the server response for the same string as our payload.  If the server response contains `<b>rs0n</b>`, the server-side code is bulding the DOM and returning it.  
    - After checking the server response, we don't see the payload reflected, but we do see an [inline JavaScript code block](https://www.geeksforgeeks.org/how-does-inline-javascript-work-with-html/) that clearly shows the value being taken from the URL and appened to the DOM after the page has loaded, so we can be confident that this unexpected behavior is happening on the client-side via this inline JavaScript:
```
<script type="text/javascript">
        function getQueryParameter(name) {
            const urlParams = new URLSearchParams(window.location.search);
            return urlParams.get(name);
        }

        function displayWelcomeMessage() {
            const userName = getQueryParameter('name');
            if (userName) {
                document.body.innerHTML = `<h1>Welcome ${userName}</h1>`;
            } else {
                document.body.innerHTML = `<h1>Welcome Guest</h1>`;
            }
        }

        window.onload = displayWelcomeMessage;
    </script>
```

### Step 4: Weaponizing The Break

For each of our injections, we now have a good idea about what mechanism we are targeting.  Our last step to finding an injection vulnerability with impact is to weaponize the unexpected behavior.  This is done by mapping your understanding of why the break is occurring to your knowledge of the possible attacks related to that mechanism.  

- Server-Side Injection | `/fetch?dest=safeapp.com@`
    - Server-side injections occur when user-controlled input is passed to a specific method without being sanitized.  To understand how we can weaponize this behavior, we need to know what method the payload is being passed to.  
    - We know that the value of the dest parameter is being converted to a URL, so it's a safe guess that the application is trying to make an HTTP Request of some kind.  We can confirm that by trying to get the application to make a request to a web server we control.  We can easily do this with [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator), sending a request to `/fetch?dest=[BURP_COLLABORTOR_DOMAIN]`.
    - Sending that request resulted in an HTTP Request being sent to our Collaborator server, confirming our assumptions.
    - Looking at our [Server-Side Injections](#server-side-injections) section of this methodology, we see that [Server-Side Request Forgery (SSRF)](https://portswigger.net/web-security/ssrf) allows attackers to force the application to make an unexpected HTTP Request *and* occurs when developers pass user-controlled input to a method like `node-fetch`.  This is our best chance for weaponizing this break.
    - *Remember, you still need to show IMPACT with SSRF by getting a successful HTTP Request on an internal service that you would not be able to access otherwise.  Getting data back from that service is better, but as long as you can have an effect on the application, that will demonstrate that you have an SSRF and not just an External Service Interaction.*

- Database Injection | `/search?q=rs0n"`
    - We know this is a database injection and we are assuming it's going to some form of SQL Database.  We're also not getting any error messages back, so we have to guess at what our query actually looks like when it's sent to the database.  All of this tells me that we are likely looking at a [Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind).  
    - It will take some trial and error to figure out HOW to weaponize this, but with database injections there are typically two goals: Exfiltrate sensitive data or Bypass Authentication.  Since this is clearly a search mechanism, there is no auth to bypass, so we will focus on exfiling data.  
    - We know that sending the `"` causes a 500 response, so let's see if we can **add characters** to the user-controlled input and get a 200 response back.  
    - After some testing, we find that sending `/search?q=rs0n";--+` causes the server to again return a 200 Response and an empty JSON object.  Since the `;` is used to end a query in MySQL and `--+` notates all data after is a comment, we can safely assume we have identified that the target is a MySQL Database and our query currently looks like this: `SELECT * FROM main_table WHERE data CONTAINS "rs0n";--+";`
    - Since this is a Blind SQL Injection, we won't be able to easily exfiltrate data, so we need to find a `True` and `False` state of the query.  Let's try searching for something else.  Sending `/search?q=a";--+` results in a 200 Response a JSON Object with several results.  These results will allow us to determine between `True` and `False` results for any [nested](https://www.mysqltutorial.org/mysql-basics/mysql-subquery/) or [union](https://www.w3schools.com/sql/sql_union.asp) queries we make.
    - We can now write a script that uses nested queries and use our True/False state to exfiltrate data **one byte at a time**.

- Client-Side Injection | `/welcome?user=<b>rs0n</b>`
    - Since the injection is caused by inline JavaScript, we can see exactly what our options are for weaponizing it.  The value of the name parameter is being appended to the body via the `innerHtml()` method here: ```document.body.innerHTML = `<h1>Welcome ${userName}</h1>`;```
    - For client-side injections, our goal is to force a victim to execute malicous JavaScript the developers did not intend.  To do that, we first need to get malicious JavaScript to execute in our client, then we will determine how to craft a payload that will have an impact on our victim, and finally we will determine how to deliver the payload to our victim.
    - Now that we have HTML Injection, we just need to improve that to JavaScript execution.  The easiest way to do this is to just add a `<script>` element designed to execute JavaScript, so let's try sending the following payload: `/welcome?user=rs0n</h1><script>alert(1)</script><h1>`
    - After sending the payload we see the elements render in the DOM successfully, but no alert was fired.  What's going on??  They are not using React or any other front-end library that would have JSX, it's just vanilla JavaScript using the `innerHtml()` method.  Let's do some research on that method...
    - After doing some [reseach](https://samy.blog/element.innerhtml-and-xss-payloads/) on the `innerHtml()` method and how it effects cross-site scripting attacks, I've found the solution.  The `innerHtml()` method does not work with `<script>` tags (too much to get into here, but it's super interesting, I recommend you do your own research!).  However, `<img>` tags with the `onerror` attribute do execute through the method.
    - Sending the following payload successfully executed JavaScript in my browser, giving a successful Cross-Site Scripting (XSS) attack: `/welcome?user=%3Ch1%3Eharrison%3C/h1%3E%3Cimg%20src=%27X%27%20onerror=alert(1)%20/%3E`
    - I can now weaponize and deliver this attack just like any other XSS

## Client-Side Injections

*GOAL: Attacker's user-controlled input forces the DOM to load in a way that the developers did not intend'*

<div>
  <a href="https://youtu.be/cnL7CB-Gak0"><img src="static/client-side-injections.png" width="300px" alt="Youtube Thumbnail"></a>
</div>

[YouTube Video - Bug Bounty Hunting for Client-Side Injection Vulnerabilities | Part I](https://youtu.be/cnL7CB-Gak0)

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
        - Send unexpected characters (Ex: All possible ASCII characters in Unicode, Hex, and Double Hex)
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
        - Server-Side Prototype Pollution (SSPP)
            - Node:
        - Insecure Deserialization
        - File Inclusion
        - XML External Entity (XXE)
- **Output**:
    - Application Behaves Unexpectedly
    - That Behavior Has a Negative Impact on Sensitive Customer Data
    - Explain Impact:
        - 

## Database Injections
- *GOAL: Attacker's user-controlled input forces the application to make a database query the developers did not intend*
- **Input**: Single Attack Vector w/ Possible Injection
- SQL Injection
    - MySQL
    - MSSQL
    - PostGRES
    - 
- NoSQL Injection
- **Output**:
    - Application Behaves Unexpectedly
    - That Behavior Has a Negative Impact on Sensitive Customer Data
    - Explain Impact:
        - 