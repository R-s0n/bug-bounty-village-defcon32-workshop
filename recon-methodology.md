# My Full Bug Bounty Hunting Methodology - Recon

*GOAL: Find Every Possible Target & Attack Vector*

- Attack Vector:
    - HTTP Verb
    - Domain
    - Endpoint
    - Injection Point

- *Ebb & Flow* - Your hunting should come "in" and "out" of this recon methodology like the ocean tides. Move down the list until you have 3-5 attack vectors on a target URL. Spend some time testing those attack vectors, but not too long. You can always return to them later. When you feel stuck, put a "pin" in those attack vectors and go back to an earlier part of the recon methodology. Try new tools/techniques, anything you can think of to expand your knowledge of their attack surface. Then choose 3-5 new attack vectors and try again. Repeat until you're a millionaire, or you need a break, whichever comes first.


# Core Recon Workflow

## Finding Apex Domains

- **Input**: Company Name
- Web Scraping
- Google Dorking
- Cloud IP Ranges
- Autonomous System Number (ASN)
- Acquisitions & Mergers
- OSINT
- LinkedIn + GitHub
- **Output**: List of Apex Domains

## Finding Live Web Applications

- **Input**: Apex Domain
- Apex Domain -> List of Subdomains
    - Amass
    - Web Scraping
    - Brute Force
    - Link Discovery
    - Cloud IP Ranges
    - Marketing & Favicon
- List of Subdomains -> List of Live URLs
    - Consolidate
    - Resolve Subdomains to IPs
    - Port Scanning
    - Test for Live Web App
- **Output**: List of URLs Pointing to Live Web Applications

## Choosing Target URLs

- **Input**: List of URLs Pointing to Live Web Applications
- Wide-Band Scanning
    - Nuclei
    - Semgrep
- Choosing an App Worth Your Time
    - Screenshots
    - Tech Stack
    - NPM Packages
    - Certificates
- **Output**: List of URLs Hosting Web Applications Worth Your Time

## Enumeration

- **Input**: URL Pointing to Live Web Application Worth Your Time (Target URL)
- Injection Attack Vectors
    - Endpoints
    - Parameters
    - HTTP Verbs
    - Headers/Cookies
- Logic Attack Vectors
    - localStorage
    - Mechanisms
    - Roles
    - Database Queries
- **Output**: List of Attack Vectors Worth Your Time



# Findind Bugs w/ Recon

## Leaked Secrets (In-App)

- **Input**: URL Pointing to Live Web Application Worth Your Time (Target URL)
- 
- **Output**: Data Valuable to an Attacker
    - How Does This Data Effect Customer Data:

## Leaked Secrets (Web Scraping)

- **Input**: Company Name
- 
- **Output**: Data Valuable to an Attacker
    - How Does This Data Effect Customer Data:

## Leaked Secrets (GitHub)

- **Input**: Company Name, Employee Names, Company GH Org
- 
- **Output**: Data Valuable to an Attacker
    - How Does This Data Effect Customer Data:

## CVE Spraying

- **Input**: List of URLs Pointing to Live Web Applications
- 
- **Output**: Valid CVE Found on Target's Attack Surface
    - How Does This CVE Effect Customer Data: