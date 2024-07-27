# My Full Bug Bounty Hunting Methodology - Recon

*GOAL: Find Every Possible Target & Attack Vector*

- An **Injection** Attack Vector is the unique combination of the following four things in an HTTP Request:
    - HTTP Verb
    - Domain:Port
    - Endpoint
    - Injection Point

- A **Logic** Attack Vector is one of the following four things:
    - Overly Complex Mechanism
    - Database Query Using ID From HTTP Request
    - Granular Access Controls
    - "Hacky" Implementations

- *Ebb & Flow* - Your hunting should come "in" and "out" of this recon methodology like the ocean tides. Move down the list until you have 3-5 attack vectors on a target URL. Spend some time testing those attack vectors, but not too long. You can always return to them later. When you feel stuck, put a "pin" in those attack vectors and go back to an earlier part of the recon methodology. Try new tools/techniques, anything you can think of to expand your knowledge of their attack surface. Then choose 3-5 new attack vectors and try again. Repeat until you're a millionaire, or you need a break, whichever comes first.


# Core Recon Workflow

## Finding Apex Domains

*SUMMARY: Some bug bounty programs have a "Wide Open Scope", meaning you are free to submit reports on any asset you find that belongs to the company.  For programs like these, we don't have any domains to start with, so we need to discover [Apex Domains](https://help.easyredir.com/en/articles/453072-what-is-a-domain-apex) as a starting point for our recon.*

### Example Programs:
- [US Department of Defense (DoD)](https://hackerone.com/deptofdefense)
- [Tesla](https://bugcrowd.com/tesla)

**Input**: *Company Name*

- Web Scraping
- Google Dorking
- Cloud IP Ranges
- Autonomous System Number (ASN)
- Acquisitions & Mergers
- OSINT
- LinkedIn + GitHub
- [Marketing & Favicon](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#trackers) - Tracking cookies and Favicons can also be used to identify apps that belong to the target company.  Basically, if you find another application using tracking cookies with the same ID or using the same Favicon as applications known to belong to this company, it's very likely to be owned by the target company.

**Output**: *List of Apex Domains*

## Finding Live Web Applications

*SUMMARY: Each apex domain in scope will have several [subdomains](https://en.wikipedia.org/wiki/Subdomain) available that host their own web application or service.  Your goal as a bug bounty hunter is to find as many of the available subdomains as possible.  Once you have a list of subdomains from a wide range of techniques, you will need to consolidate them into a single list of unique subdomains.  Keep in mind that these domains point to IP Addresses, and applications may act differently if you access them by their IP directly, so the next step is to resolve the [Fully-Qualified Domain Names (FQDNs)](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to the IP Address(s) they point to and add those to the list of possible targets.  Finally, applications may be running on those targets outside of the normal web server ports 80 and 443, so scanning for open ports can help find targets that other hunters miss.  At this point, you will have a list of unique FQDNs and IP Addresses/Open Ports.  Probe each target on the list with HTTP Requests to identify which of the targets is currently hosting a live web application.*

**Input**: *Apex Domain*

- **Apex Domain -> List of Subdomains**
    - [Amass](https://github.com/owasp-amass/amass) - Amass (by OWASP) is the backbone of my recon methodology at this stage.  It does many of the steps below in one tool, as well as DNS and ASN discovery.  Amass typically finds 80% of the total subdomains I discover, but keep in mind that everyone else can easily use Amass as well.  When it comes to recon, the bugs are at the far ends of the bell curve.
    - [Web Scraping](https://www.imperva.com/learn/application-security/web-scraping-attack/#:~:text=Web%20scraping%20is%20the%20process,data%20stored%20in%20a%20database.) - Your goal here is to discover as many subdomains as you can using public resources on the web.  Resources can range from public search engines like Google to APIs that maintain certificate registration data.  Always try to be creative and find new ways to scrape public web sources for sudomains.  If you can come up with a technique that no one has thought of, you might find subdomains no one else has tested.
        - [Sublist3r](https://github.com/huntergregal/Sublist3r)
        - [Assetfinder](https://github.com/tomnomnom/assetfinder)
        - [GetAllUrls(GAU)](https://github.com/lc/gau)
        - [Certificate Transparency Logs (CRT)](https://github.com/google/certificate-transparency)
        - [Subfinder](https://github.com/projectdiscovery/subfinder)
    - [Brute Force](https://blog.projectdiscovery.io/recon-series-2/#:~:text=Subdomain%20brute%20forcing%20involves%20using,determine%20which%20subdomains%20are%20valid.) - Brute forcing for subdomains is fairly simple and exactly what it sounds like.  Simply take a wordlist of possible subdomains and attempt to resolve the full domain with each subdomain in the wordlist.
        - [ShuffleDNS](https://github.com/projectdiscovery/shuffledns)
        - [CeWL](https://github.com/digininja/CeWL) + ShuffleDNS - CeWL crawls a website and builds a wordlist dynamically based on the most commonly used words in the target app.  Using CeWL to build a word list, then passing that list to ShuffleDNS, can be a great way to find subdomains that follow a naming convention that might show up in the DOM.
    - Link Discovery - At this point, you will have a list of subdomains that *could* point to live web application.  For the next stage of recon, you will use tools to crawl the subdomains that point to live web applications.  To do that, you first need to consolidate your list of subdomains and identify which of the FQDNs points to a live web app.  There's more information on how to do that in the list below, but remember that you need do this twice:  Once before Link Discovery, and once at the end after all other tools have completed.
        - [GoSpider](https://github.com/jaeles-project/gospider)
        - [Subdomainizer](https://github.com/nsonaniya2010/SubDomainizer)
    - [Cloud IP Ranges](https://www.daehee.com/blog/scan-aws-ip-ssl-certificates) - I've built an automated tool called [Clear-Sky](https://github.com/R-s0n/Clear-Sky) to do this.  Keep in mind that loading the certificate data can take over 24 hours, depending on your Internet speed.
- **List of Subdomains -> List of Live URLs**
    - Resolve Subdomains to IPs - Now that you have a list of subdomains, you can resolve each of them to identify the IP Address of possible targets.  Keep in mind that this is *very* prone to false positives, so you need to manually verify each of the IP Addresses before you start testing.  If the target's infrastructure is on-premises, make sure the IP is included in the [CIDR Ranges](https://blog.ip2location.com/knowledge-base/what-is-cidr/) of the ASNs.  If their infrastrucutre is in the cloud, it's very possible that their IPs are not static.  Manually verify by accessing the IP address directly through the browser (Example: https://192.168.1.1).  By accessing the application by the IP directly, you may be able to bypass security controls or cause it to act differently than it would if you had accessed it throught he domain.  This also changes the [Host Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host), and may allow you to access a new application altogether.  
    - Port Scanning - Once you've got a valid list of IP Addresses that are confirmed to belong to the target, you can run a port scan to see what other services might be available to an attacker.  Ideally, you can find a web application running on a different port, such as 8080 or 8443.  
        - [DNMasscan](https://github.com/rastating/dnmasscan) - This tool resolves the IP Address and does port scanning.  Just remember to verify the results before testing.
    - Consolidate - As I mentioned before, you'll need to write an algorithm that consolidates the subdomains into a list of unique subdomains.  You should also verify that all the subdomains belong to the original Apex Domain.  Many of these tools, especially the crawlers, will return domains that are not "in scope".
    - Test for Live Web App - Finally, you can test your list of unique subdomains/IP addresses/ports to find which of those are pointing to a live web application.  The two tools I use to do this are [httprobe](https://github.com/tomnomnom/httprobe) and [httpx](https://github.com/projectdiscovery/httpx).

**Output**: *List of URLs Pointing to Live Web Applications*

## Choosing Target URLs

*SUMMARY: Now that you have a list of URLs pointing to a live web application, you'll need to decide which of these targets is worth your time to manually test.  There are several signs that a target application may be worth your time, but ultimately you are looking for a target that has the greatest likelihood of having a valid vulnerability.  Outdated NPM Packages, expired certificates, or an old copyright might mean a web application hasn't been maintained by the company and could be vulnerable to newer attack techniques.  Targets that are deep into recon and very difficult to find will be missed by other researchers.  New features or domains also may not have been tested by other researchers.  Over time, you will build up your own list of "signs" that tell you a target may be vulnerable.  Choose two or three at first, then move on to the next step.  If you get stuck, come back to this step and choose a few others, then try again.*

**Input**: *List of URLs Pointing to Live Web Applications*

- **[Wide-Band Scanning](https://www.linkedin.com/feed/update/urn:li:activity:6849314055283466240/)** - Before you start looking into each application one by one, you can start to narrow your search down by using automated tools that scan each URL for thousands of known vulnerabilities and misconfigurations.  Not only can this be a way to find bugs (although it's rare since everyone does this), but the results of these scans can help you identify an application that is not being well maintained.  The more high impact findings you have on a target, the greater chance of finding other bugs when you being to do manual Injection/Logic testing.
    - [Nuclei](https://github.com/projectdiscovery/nuclei) - Nuclei by Project Discovery is the backbone of my vulnerability scanning methodology.  Not only do that have a TON of great [templates](https://github.com/projectdiscovery/nuclei-templates) already created, but you can [create your own](https://docs.projectdiscovery.io/templates/introduction) with a simple YAML file.  I will go into more detail about building custom templates to find bugs other researchers are missing in the [CVE Spraying](#cve-spraying) section below.
    - [Semgrep](https://github.com/semgrep/semgrep) - Semgrep is a phenomonal open-source [Static Code Analysis Tool (SAST)](https://owasp.org/www-community/Source_Code_Analysis_Tools) that uses [Abstract Syntax Trees (ASTs)](https://medium.com/hootsuite-engineering/static-analysis-using-asts-ebcd170c955e#:~:text=Static%20code%20analysis%20means%20analyzing,and%20even%20some%20semantic%20mistakes.) to evaluate application code and identify patterns that could be exploited by an attacker.  For most bug bounty programs you won't have access to the application's server-side code, but you still have access to the client-side code.  Run all client-side JavaScript through Semgrep to identify any possible DOM injections or other code patterns that might show the application would be a target worth your time.  If you're lucky when evaluating a React app, the developers did not properly [obfuscate the webpack](https://github.com/javascript-obfuscator/webpack-obfuscator), meaning you can [download all of the raw React files and scan them for known vulnerabilities](https://youtu.be/kbwFgLYB4Y0) using Semgrep.
- **Choosing an App Worth Your Time** - Now that you have a picture of what vulnerabilities and misconfigurations exist in each app's attack surface, you can start to dig into the app itself.  There are an infinate number of things that you could be looking for, and there's really no way to standardize this part of the methodlogy.  Ultimately, you need to decide on a few URLs pointing to an app that gives you the greatest chance of finding a bug.  This is a skill you have to develop over time, there's no substitute for hard work and experience here.  Once you start to find and submit valid bugs, you will be able to tie those bugs to what you saw in the app and that will become a "Pointer" for you in the future.  When you see the same configuration, you will check for the same vulnerability.  Over time you will build up a list of many Pointers and this step will become much easier.  Remember, just like when you're working out to build muscle, if you're not pushing yourself you won't grow.  The feeling of being frustrated means you are growing, just like the feeling of pain in your muscles means you're building muscle.  Embrace the frustration, dive into it head first, and push through it.
    - Screenshots - This is one of the quickest and easiest ways to find target apps that might be vulnerable.  Look for major variations, error messages, development environments, etc.
        - [Nuclei](https://github.com/projectdiscovery/nuclei-templates/blob/main/headless/screenshot.yaml) - Nuclei has a headless browser template that does very well at taking screenshots.
        - [EyeWitness](https://github.com/RedSiege/EyeWitness) - In addition to taking screenshots, EyeWitness also gathers information about the target application that can be useful.  If you want something a bit more robust than the Nuclei template, this is my go-to tool.
    - Tech Stack - It's always a good idea to test against applications built using technology you are familiar with and enjoy testing.  If I see a URL pointing to an app built in the [MERN stacks](https://www.mongodb.com/resources/languages/mern-stack) and hosted in AWS, I'm excited to jump in!  On the other hand, if I see .NET apps hosted in Azure, I'll probably save that one for later.
        - [Wappalyzer](https://www.wappalyzer.com/)
        - [BuiltWith](https://builtwith.com/)
    - [NPM Packages](https://www.w3schools.com/nodejs/nodejs_npm.asp) - NPM Packages are public JavaScript libraries that are used to supplement custom application code.  As always, you won't have access to the NPM packages the developers are using on the server-side, but you can easily enumerate all of the client-side NPM packages.  More importantly, you can identify the version of these packages, as well as if that version has any known vulnerabilities.  *Remember, just because an NPM package has a known vulnerability, **it does not mean that vulnerability exists in the target application**.  That vulnerability will almost always be in a single [method](https://www.w3schools.com/js/js_object_methods.asp) in the package.  If the developers do not use that method, they are not vulnerabile to that CVE.*  However, even if it's not vulnerable, a target application with outdated NPM packages can be a great sign that an application isn't being well maintained and may have other vulnerabilities.
        - [https://github.com/RetireJS/retire.js](https://github.com/RetireJS/retire.js)
    - [Certificates](https://www.cisa.gov/news-events/news/understanding-website-certificates) - Any target application that has issues with their certificate could point to an application that's not being actively maintained.  Or, even better, it's a test/development app that the company was *hoping* you wouldn't find.  Just remember that appending the port to the end of the URL can lead to false positives.  If you access https://floqast.app:443, you will still access the same application, but the certificate will not include the port and cause a false certificate mismatch finding.  The browser corrects this issue for you, but scanning tools like Nuclei will not.
        - [Expired Certificate](https://sematext.com/glossary/ssl-certificate-expiration/) - This could show that the application is not being actively maintained.  Check any dates you can find to confirm.
        - [Mismatched Certificate](https://www.globalsign.com/en/blog/what-is-common-name-mismatch-error) - This could show that the app has recently gone through a domain change.  There could be a lot of other massive changes happening at the same time.  This could be a great candidate for future bugs.
        - [Self-Signed Certificate](https://www.entrust.com/resources/learn/what-is-a-self-signed-certificate) - These are my favorite!  You know something has gone wrong here, a self-signed cert should never be public.  It's very likely this is a dev/test app that has not gone through any security testing.  Go nuts!!

**Output**: *List of URLs Hosting Web Applications Worth Your Time*

## Enumeration

*SUMMARY: Now that you have a few target URLs worth your time, your goal is to find an Attack Vector.  First, crawl and use brute force to identify all available endpoints.  Test each of those endpoints for parameters, Headers, Cookies, and valid HTTP verbs.  You should be able to identify four or five Attack Vectors that might be vulnerable to an injection attack.  Do the same for data and code stored on the client-side, as well as any mechanisms, roles, or database queries that could possibly be vulnerable to an injection attack.  Now you're ready to take those attack vectors and thoroughly test them using the Injection or Logic methodologies.*

**Input**: *URL Pointing to Live Web Application Worth Your Time (Target URL)*

- **Injection Attack Vectors** - If you are interested in testing for injection vulnerabilities, focus your efforts on enumerating the following four data points.  Remember that all injection vulnerabilities happen because user-controlled input is not properly [sanitized](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) before it is processed by the application.  It doesn't matter if the injection occurs in the [client-side](https://ars0nsecurity.com/pages/methodology#:~:text=Client%2DSide%20Codebase%20Testing), [server-side](https://ars0nsecurity.com/pages/methodology#:~:text=Server%2DSide%20Codebase%20Testing), or [database](https://ars0nsecurity.com/pages/methodology#:~:text=Database%20Operation%20Testing).  All injections are caused by user-controlled input in the HTTP request that, when processed by the application, causes the app to act in a way the developers did not intend.  That behavior (and the impact of the vulnerability) changes dramatically based on where the injection occurs, but how we got there is always the same.
    - [Endpoints](https://medium.com/@alostwarrior/how-to-find-endpoints-in-web-applications-541ee1225b05) - I prefer calling them endpoints, but they are also called routes or paths.  Either way, this is the part of the URL that points to a unique piece of the application.  For example, navigating to https://floqast.app/login loads a page with a form to log into the application.  However, navigating to the https://floqast.app/login/soo endpoint loads an entirely different form that allows the user to log in through a [Single Sign-On (SSO)](https://www.cloudflare.com/learning/access-management/what-is-sso/) implementation.  Your goal here is to find all available endpoints to give yourself the greatest chance of finding a valid bug.  If you can find endpoints that other hunters miss because you're being creative, you will be the first to test the mechanisms on that endpoint, greatly increasing your chances of finding a vuln.
        - Manual - The first step you should take is to manually click through the application to find all the endpoints the developers expect you to find through typical navigation.  These will probably be tested the most by other researchers, so it's good to get a picture of the app before you start fuzzing for hidden endpoints.
        - Automated Crawl - Next, use an automated crawler to make sure you didn't miss anything when manually crawling the app.  Automated crawlers will pull endpoints out of client-side JavaScript and other places a typical user may miss.
            - [Portswigger's Burpsuite](https://portswigger.net/burp/documentation/desktop/automated-scanning/webapp-scans/full-crawl-and-audit)
            - [Project Discovery's Katana](https://github.com/projectdiscovery/katana)
            - [Caido](https://caido.io/)
        - Fuzzing For Endpoints - Finally, you can use a brute-force technique to test the application for hidden endpoints.  It's as simple as loading a wordlist of possible endpoints and looping through them, making an HTTP request for each word (Ex: https://floqast.app/word_from_wordlist).  
            - [Fuzz Faster U Fool (FFUF)](https://github.com/ffuf/ffuf)
            - [Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)
            - [Burp Content Disovery](https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/content-discovery)
    - [Parameters](https://hacktivator.medium.com/bug-bounty-find-hidden-parameters-ea219b01e7ca) - Now that you have as many endpoints as you can find, you'll want to test each of them to find all the possible ways user-controlled input can be submitted to the application.  In most cases, the best targets for injection attacks are [parameters](https://www.semrush.com/blog/url-parameters/).  Parameters are added to an HTTP request, either at the end of the URL or the body of the request.  Parameters are user-controlled input that you *know* is processed by the application in some way.
        - [Arjun](https://github.com/s0md3v/Arjun)
        - [Burp Param Miner](https://github.com/PortSwigger/param-miner)
    - [HTTP Verbs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) - For some reason, this is an area of enumeration I see many researches missing.  Each endpoint you discover will have an HTTP verb associated with it.  Most will be GET requests to READ data from the database, but some (like form submissions) will be sent via a POST, PUT, UPDATE, PATCH, etc.  These requests will contain a body with additional parameters is a specific [MIME type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types).  You should test each endpoint for every possible HTTP verb.  It is very common to find endpoints that take multiple HTTP Verbs and have completely different functionality.  This is why the HTTP verb is part of determining whether an attack vector is unique.
        - [appscan by `gh0st`](https://github.com/osm6495/appscan)
    - [Headers](https://developer.mozilla.org/en-US/docs/Glossary/HTTP_header)/[Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cookie) - Finally, spend a bit of time fuzzing for hidden Headers and Cookies.  In some cases, these can be used as attack vectors for injection attacks.  Finding hidden headers or cookies may also give you access to functionality that isn't meant for typical users.  Maybe it's legacy code that was never removed because the developers simply stopped the header/cookie from being sent?  Or maybe it's a debug function that wasn't removed before it was pushed to prod?  These things happen all the time and can easily be found by sending HTTP requests with additional headers/cookies and looking for a variation in the server's response.
        - [Burp Param Miner](https://github.com/PortSwigger/param-miner)
        - [Fuzz Faster U Fool (FFUF)](https://github.com/ffuf/ffuf)
        - [Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)
- **Logic Attack Vectors** - If you are interested in testing for logic vulnerabilities, you will need to deeply understand the application.  Before you invest that time, though, make sure that the app is complex enough to justify the effort.  Just like with injection vulnerabilities, you are trying to find an attack vector.  Instead of user-controlled input in the HTTP request, logic attack vectors come from developers not following best practices and/or building overly complex systems.  Developers are almost always under a *lot* of pressure to deliver new features quickly.  When a vulnerability reaches production, it's not that the developer was lazy or didn't care.  They simply opened a ticket that said they needed to build a feature that does XYZ, then they wrote the code that accomplished that goal as simply as possible and moved onto the next ticket.  They were probably also building a service that was part of a long chain of different services sending data between each other, all built by different development teams.  This complexity is where logic vulnerabilities can be found.
    - Dev Tools - Looking through the data in the [Developer Tools](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/Tools_and_setup/What_are_browser_developer_tools) of your browser can be a great way to quickly find out if the developers are using best practices.  
        - Client-Side Data Storage - Developers have the option of storing data in the client's browser through mechanisms like `localStorage` and `sessionStorage`.  While these can be a great option for [improving an application's performance](https://medium.com/@MakeComputerScienceGreatAgain/leveraging-the-power-of-localstorage-a-guide-to-efficient-client-side-data-management-d20095733e16) or building new functionality quickly in a [Single-Page Application (SPA)](https://developer.mozilla.org/en-US/docs/Glossary/SPA), there are significant security risks to using these storage options for sensitive data.  If you find an application that has a large amount of data in either `localStorage` or `sessionStorage`, especially any sensitive data, that's a great sign that this application is worth your time.
        - [Cookies & Cookie Flags](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) - Next, you will want to look through the cookies stored in the browser after you have logged in.  *Keep in mind that applications without authentication are not good targets for logic testing because you will be kept away from most of the mechanisms you will need to test.*  Once you've logged in, look through the cookies and identify any that are used to [establish a session](https://securiti.ai/blog/session-cookies/).  For each cookie that is used to establishe a session, check for the following:
            - Data Stored in Cookie - Some cookies contain data that can be read in plain text, often after a bit of decoding.  Cookies that contain data are most commonly encoded using [Base64](https://en.wikipedia.org/wiki/Base64).  The most well-known example of this is a [JSON Web Token (JWT)](https://jwt.io/introduction).
            - Cookie Signed for Integrity - If you find a cookie that contains data, check to see if that cookie has been [signed for integrity](https://eitca.org/cybersecurity/eitc-is-wasf-web-applications-security-fundamentals/session-attacks/cookie-and-session-attacks/examination-review-cookie-and-session-attacks/what-is-the-purpose-of-signing-cookies-and-how-does-it-prevent-exploitation/)
            - Secure Cookie Flag
            - httpOnly Cookie Flag
            - sameSite Cookie Flag
        - Client-Side JavaScript
        - State/Props 
    - Mechanisms
    - Roles
    - Database Queries

**Output**: *List of Attack Vectors Worth Your Time*



# Findind Bugs w/ Recon

## Leaked Secrets (In-App)

**Input**: *URL Pointing to Live Web Application Worth Your Time (Target URL)*

- 

**Output**: *Data Valuable to an Attacker*

How Does This Data Effect Customer Data:

## Leaked Secrets (Web Scraping)

**Input**: *Company Name*

- 

**Output**: *Data Valuable to an Attacker*

How Does This Data Effect Customer Data:

## Leaked Secrets (GitHub)

**Input**: *Company Name, Employee Names, Company GH Org*

- 

**Output**: *Data Valuable to an Attacker*

How Does This Data Effect Customer Data:

## CVE Spraying

**Input**: *List of URLs Pointing to Live Web Applications*

- 

**Output**: *Valid CVE Found on Target's Attack Surface*

How Does This CVE Effect Customer Data: