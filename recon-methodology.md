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
    - Amass
    - Web Scraping
    - Brute Force
    - Link Discovery
    - Cloud IP Ranges
    - Marketing & Favicon
- List of Subdomains -> List of Live URLs
    - Resolve Subdomains to IPs
    - Port Scanning
    - Consolidate
    - Test for Live Web App

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
    - How Does This Data Effect Customer Data:

## Leaked Secrets (Web Scraping)

**Input**: *Company Name*

- 

**Output**: *Data Valuable to an Attacker*
    - How Does This Data Effect Customer Data:

## Leaked Secrets (GitHub)

**Input**: *Company Name, Employee Names, Company GH Org*

- 

**Output**: *Data Valuable to an Attacker*
    - How Does This Data Effect Customer Data:

## CVE Spraying

**Input**: *List of URLs Pointing to Live Web Applications*

- 

**Output**: *Valid CVE Found on Target's Attack Surface*
    - How Does This CVE Effect Customer Data: