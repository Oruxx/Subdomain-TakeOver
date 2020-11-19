#!/usr/bin/env python3
import requests,urllib3
import argparse
import re
import os
import dns.resolver
import socket
from progress.bar import Bar
#Author Orux :)) github:orux-0

#class colors
#style  text color    background color
#[5     ;32           ;34m
#ForeGround
class F:
    black   = '\033[30m'
    red     = '\033[31m'
    green   = '\033[32m'
    yellow  = '\033[33m'
    blue    = '\033[34m'
    poorple = '\033[35m'
    cyan    = '\033[36m'
    white   = '\033[37m'
    end   = '\033[39m'
#Backgorund
class B:
    black   = '\033[40m'
    red     = '\033[41m'
    green   = '\033[42m'
    yellow  = '\033[43m'
    blue    = '\033[44m'
    poorple = '\033[45m'
    cyan    = '\033[46m'
    white   = '\033[47m'
    end   = '\033[49m'
#Special
class S:
    T='\033[5;36m' 
    Tend='\033[0m'
    BRIGHT    = '\033[1m'
    DIM       = '\033[2m'
    NORMAL    = '\033[22m'
    RESET_ALL = '\033[0m'
    RED = "\033[1;31m"
    GREEN = "\033[1;32;0m"
    OKBLUE = "\033[94m"
    WHITE = "\033[0;37m"

VulnText = ["<strong>Trying to access your account", 
"Use a personal domain name", 
"The request could not be satisfied", 
"Sorry, We Couldn't Find That Page", 
"Fastly error: unknown domain", 
"The feed has not been found", 
"You can claim it now at", 
"Publishing platform",                        
"There isn't a GitHub Pages site here",                       
"No settings were found for this company",
"Heroku | No such app", 
"<title>No such app</title>",                        
"You've Discovered A Missing Link. Our Apologies!", 
"Sorry, couldn&rsquo;t find the status page",                        
"NoSuchBucket", 
"Sorry, this shop is currently unavailable", 
"<title>Hosted Status Pages for Your Company</title>", 
"data-html-name=\"Header Logo Link\"",                        
"<title>Oops - We didn't find your site.</title>",
"class=\"MarketplaceHeader__tictailLogo\"",                        
"Whatever you were looking for doesn't currently exist at this address", 
"The requested URL was not found on this server", 
"The page you have requested does not exist", 
"This UserVoice subdomain is currently available!", 
"but is not configured for an account on our platform", 
"<title>Help Center Closed | Zendesk</title>", 
"Sorry, We Couldn't Find That Page Please try again"]

# db urls with data
class DB:
    def __init__(self, subdomain,dns,vuln,code):
        self.subdomain = subdomain
        self.dns = dns
        self.vuln = vuln;self.code = code

    def __repr__(self):
        return self.subdomain
db = []

#Functions
def parse():
    parser = argparse.ArgumentParser(description="Description: Subdomain TakeOver Scan, Author: Orux")
    parser.add_argument('-l','--list',help=f'python3 {__file__} [-l, --list] list of domains',required=True)
    args = parser.parse_args()
    domainlists = args.list

    return domainlists

def valid(rd):
    urls = []
    for x in rd.readlines():
        x = re.sub(r"\s+", "", str(x))
        if x.startswith('http://'):
            pass
        elif x.startswith('https://'):
            pass
        else:
            x = f'http://{x}'
        urls.append(x)
	#print(f"{F.green}Uploading subdomains: {F.black}{len(urls)}{F.end}",end="\r", flush=True)
    print(f"{F.green}Total subdomains: {F.blue}{len(urls)}{F.end}"+" "*20)
    return urls
			
def check(urls):
    global db
    urllib3.disable_warnings()
    
#    print(len(urls))
    for x in urls:
        vulnerable = 'No'
        # Url Requests
        try:
            r = requests.get(x,timeout=5,verify=False)
            text = r.text
            code = r.status_code
            for vuln in VulnText:
                if vuln in text:
                    vulnerable = 'Yes'
        except requests.exceptions.ConnectionError:
            code = ''

		# Dns Resolve
        resolver = dns.resolver.Resolver()
        resolver.nameservers=[socket.gethostbyname('8.8.8.8')]
        try:
            for z in resolver.resolve(x, 'CNAME'):
                resolv = z.target
        except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.exception.Timeout):
            resolv = ''
        if not vulnerable == 'Yes':
            print(f'{F.black}ID: {urls.index(x)} {F.green}{x} {F.yellow}CNAME: {resolv} {F.green}Vuln: {F.black}{vulnerable} {F.cyan}Status Code: {F.green}{code}{F.end}',' '*50,end='\r',flush=True)
        else:
            print(f'{F.black}ID: {urls.index(x)} {F.green}{x} {F.yellow}CNAME: {resolv} {F.green}Vuln: {F.red}{vulnerable} {F.cyan}Status Code: {code}{F.end}',' '*50)
        db.append(DB(x,resolv,vulnerable,code))
		


if __name__ == '__main__':
    d = parse()
    if d:
        if os.path.isfile(d):
            rd = open(d, 'r')
        else:
            print(f'{B.red}The given argument is not a file{B.end}')
            # print(valid(rd))
        check(valid(rd))
        for i in db:
            vuln = 0
            if i.vuln == 'Yes':
                vuln = vuln+1
                print(i.subdomain)
        print(f"Total Vuln Subdomains  {vuln}")
