# My Full Bug Bounty Hunting Methodology - Cloud

*GOAL: Find misconfigurations in public cloud infrastructure deployed by the target that exposes data*
- Targets Flaws in a **Cloud Service** Used by the Application
- Examples:
    - Misconfigurations in Infrastructure Hosted By Cloud
    - Application Code Leverages Cloud Service

## Enumerate Cloud Infrastructure and Attack Surface 
- Identify Cloud resources belonging to your target
    - Multi Cloud OSINT Search - [Cloud_Enum](https://github.com/initstring/cloud_enum) 
    - Resource identification by DNS records
        - [Fire_cloud standalone]() tool that reviews DNS records of subdomains for AWS resources
            - Can be adapted to other cloud providers very easily
        - Note that other cloud resources could be searched for and that some times these resources are hidden behind subdomains that are pointing them via CNAME registry.
            - Look for CNAME's pointing to `['amazonaws.com', 'digitaloceanspaces.com', 'windows.net', 'storage.googleapis.com', 'aliyuncs.com']`
                - Not an exhaustive list 
    - [AADInternals OSINT](https://aadinternals.com/osint/) to potentially identify new domains
        - In a powershell prompt:  
            - `import-module AADInternals`
            - `Invoke-AADIntReconAsOutsider -Domain "{target-website.com}" | format-table`
- Scraping web pages for cloud resources [Cloud Scraper](https://github.com/jordanpotti/CloudScraper)
- OSINT Search for Secrets
    - Github Search for secrets [github-users.py](https://github.com/gwen001/github-search/blob/master/github-users.py)
        - `python3 github-users.py -k {target}`
    - Github Dorks for secrets [Github-brute-dork](https://github.com/R-s0n/Github_Brute-Dork)
        - `python3 github_brutedork.py -u [USER] -t [TOKEN] -U [TARGET_USER] -o [TARGET_ORG] -v -d`
    - Use Dora to determine impact of found secrets:
        - https://github.com/sdushantha/dora#example-use-cases
    - Check any found secrets for validity
        - [https://github.com/streaak/keyhacks](https://github.com/streaak/keyhacks)
        - [https://github.com/gwen001/keyhacks.sh](https://github.com/gwen001/keyhacks.sh)
- [Nuclei Cloud Enum Templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/cloud/enum)

## Infrastructure Misconfig
- Review the services you've discovered and research most common misconfigurations of those services. Most commonly, you're looking for services that are left public or over permissioned to internet facing users. 
    - [HackTrickz Cloud](https://cloud.hacktricks.xyz/)
    - [Hacking The Cloud](https://hackingthe.cloud/)
 
## App Code -> Cloud Service
- Review HTTP traffic of the application as you're using it. Look for HTTP requests to cloud resources and try to determine how the resource is being used in the code. 
- Research ways these can be implemented in an insecure way
    - [PwnedLabs](https://pwnedlabs.io/)
        - Good for hands on learning ways that cloud apps are misconfigured/exposed 
    - [OWASP Cloud Top 10](https://owasp.org/www-project-cloud-native-application-security-top-10/)
