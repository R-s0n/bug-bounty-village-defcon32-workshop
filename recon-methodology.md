# My Full Bug Bounty Hunting Methodology - Recon

*GOAL: Find Every Possible Target & Attack Vector*

- An Attack Vector is the unique combination of the following four things in an HTTP Request:
    - HTTP Verb
    - Domain:Port
    - Endpoint
    - Injection Point

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

**Output**: *List of Apex Domains*

## Finding Live Web Applications

*SUMMARY: Each apex domain in scope will have several [subdomains](https://en.wikipedia.org/wiki/Subdomain) available that host their own web application or service.  Your goal as a bug bounty hunter is to find as many of the available subdomains as possible.  Once you have a list of subdomains from a wide range of techniques, you will need to consolidate them into a single list of unique subdomains.  Keep in mind that these domains point to IP Addresses, and applications may act differently if you access them by their IP directly, so the next step is to resolve the [Fully-Qualified Domain Names (FQDNs)](https://en.wikipedia.org/wiki/Fully_qualified_domain_name) to the IP Address(s) they point to and add those to the list of possible targets.  Finally, applications may be running on those targets outside of the normal web server ports 80 and 443, so scanning for open ports can help find targets that other hunters miss.  At this point, you will have a list of unique FQDNs and IP Addresses/Open Ports.  Probe each target on the list with HTTP Requests to identify which of the targets is currently hosting a live web application.*

**Input**: *Apex Domain*

- Apex Domain -> List of Subdomains
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
    - [Marketing & Favicon](https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#trackers)
- List of Subdomains -> List of Live URLs
    - Resolve Subdomains to IPs - Now that you have a list of subdomains, you can resolve each of them to identify the IP Address of possible targets.  Keep in mind that this is *very* prone to false positives, so you need to manually verify each of the IP Addresses before you start testing.  If the target's infrastructure is on-premises, make sure the IP is included in the [CIDR Ranges](https://blog.ip2location.com/knowledge-base/what-is-cidr/) of the ASNs.  If their infrastrucutre is in the cloud, it's very possible that their IPs are not static.  Manually verify by accessing the IP address directly through the browser (Example: https://192.168.1.1).  By accessing the application by the IP directly, you may be able to bypass security controls or cause it to act differently than it would if you had accessed it throught he domain.  This also changes the [Host Header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host), and may allow you to access a new application altogether.  
    - Port Scanning - Once you've got a valid list of IP Addresses that are confirmed to belong to the target, you can run a port scan to see what other services might be available to an attacker.  Ideally, you can find a web application running on a different port, such as 8080 or 8443.  
        - [DNMasscan](https://github.com/rastating/dnmasscan) - This tool resolves the IP Address and does port scanning.  Just remember to verify the results before testing.
    - Consolidate - As I mentioned before, you'll need to write an algorithm that consolidates the subdomains into a list of unique subdomains.  You should also verify that all the subdomains belong to the original Apex Domain.  Many of these tools, especially the crawlers, will return domains that are not "in scope".
    - Test for Live Web App - Finally, you can test your list of unique subdomains/IP addresses/ports to find which of those are pointing to a live web application.  The two tools I use to do this are [httprobe](https://github.com/tomnomnom/httprobe) and [httpx](https://github.com/projectdiscovery/httpx).

**Output**: *List of URLs Pointing to Live Web Applications*

## Choosing Target URLs

*SUMMARY: Now that you have a list of URLs pointing to a live web application, you'll need to decide which of these targets is worth your time to manually test.  There are several signs that a target application may be worth your time, but ultimately you are looking for a target that has the greatest likelihood of having a valid vulnerability.  Outdated NPM Packages, expired certificates, or an old copyright might mean a web application hasn't been maintained by the company and could be vulnerable to newer attack techniques.  Targets that are deep into recon and very difficult to find will be missed by other researchers.  New features or domains also may not have been tested by other researchers.  Over time, you will build up your own list of "signs" that tell you a target may be vulnerable.  Choose two or three at first, then move on to the next step.  If you get stuck, come back to this step and choose a few others, then try again.*

**Input**: *List of URLs Pointing to Live Web Applications*

- Wide-Band Scanning
    - Nuclei
    - Semgrep
- Choosing an App Worth Your Time
    - Screenshots
    - Tech Stack
    - NPM Packages
    - Certificates

**Output**: *List of URLs Hosting Web Applications Worth Your Time*

## Enumeration

*SUMMARY: Now that you have a few target URLs worth your time, your goal is to find an Attack Vector.  First, crawl and use brute force to identify all available endpoints.  Test each of those endpoints for parameters, Headers, Cookies, and valid HTTP verbs.  You should be able to identify four or five Attack Vectors that might be vulnerable to an injection attack.  Do the same for data and code stored on the client-side, as well as any mechanisms, roles, or database queries that could possibly be vulnerable to an injection attack.  Now you're ready to take those attack vectors and thoroughly test them using the Injection or Logic methodologies.*

**Input**: *URL Pointing to Live Web Application Worth Your Time (Target URL)*

- Injection Attack Vectors
    - Endpoints
    - Parameters
    - HTTP Verbs
    - Headers/Cookies
- Logic Attack Vectors
    - Dev Tools
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