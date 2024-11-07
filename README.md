These scripts are created for the use of ail-typo-squatting from circle. And for fully automated use trough crontab.

Usage ./automate.sh <domainlist> <outputfolder>
Looks for subdomains of the domains stored in the domainlist using subfinder.
runs ail-typo-squatting on both domains and subdomains and generates similar looking domains.
tries to filter them by registered domains using massdns.
stores this infomation in resolved.txt.
for resolveble domains it runs gowitness to make screenshots and these get stored inside the screenshot folder.
gowitness logs get stored as well.
runs the report.py script
this script generates a report in xsls format based on the outputs of the .sh script.
The output of the xsls contain registered domains, record types, IP/CNAME, screenshots for both http and https

