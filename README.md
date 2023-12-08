# RECONnaisseur - automating parts of a pentest's recon phase
This script helps you to automatically collect the most important information in the recon phase of IP networks.  
You will get:
- a full nmap scan of all TCP ports
- a limited nmap scan of the top 100 UDP ports
- a list of all hosts that are somehow alive
- a separate folder for each host that is alive, containing information about that host
- a DNS lookup for each IP that is alive
- historical DNS data for the IP, or a link to where it can be found
- a list of all open ports
- a list of all web servers found
- screenshots of all websites served
- a nikto scan of all web servers
- a CMS detection of all detected websites


## Requirements
Please make sure that the following programs are installed and available via `which`:
- nmap
- xmlstarlet
- xsltproc
- httprobe
- nikto
- eyewitness
- elinks
- cmseek

## Usage
Printing the help message:  
`./reconnaisseur.sh -h`
![reconnaisseur_help](https://github.com/riotsecurity/RECONnaisseur/assets/61002269/39047f86-0b82-4be7-aebe-39760df622ae)


Running RECONnaisseur with a list of IPs in /tmp/list, storing the output in /tmp/demo and skipping the UDP scan:  
`./reconnaisseur.sh -u /tmp/list /tmp/demo`  
![reconnaisseur_run](https://github.com/riotsecurity/RECONnaisseur/assets/61002269/ad7850a6-5f5a-40cc-b9d4-10d817dea401)


Structure of the output folder for that scan:  
![reconnaisseur_output](https://github.com/riotsecurity/RECONnaisseur/assets/61002269/2f37e5c4-a745-47e4-bcdd-e08aad331a8b)



## Author and License
Author: Timo Sablowski  
License: GNU GPLv3  
