# My Full Bug Bounty Hunting Methodology - Recon

*GOAL: Find Every Possible Target & Attack Vector*

- Attack Vector:
    - HTTP Verb
    - Domain
    - Endpoint
    - Injection Point



# Core Recon Workflow

## Finding Apex Domains

- **Input**: Company Name
- 
- **Output**: List of Apex Domains

## Finding Live Web Applications

- **Input**: Apex Domain
- 
- **Output**: List of URLs Pointing to Live Web Applications

## Choosing Target URLs

- **Input**: List of URLs Pointing to Live Web Applications
- 
- **Output**: List of URLs Hosting Web Applications Worth Your Time

## Enumeration

- **Input**: URL Pointing to Live Web Application Worth Your Time (Target URL)
- 
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