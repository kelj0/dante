#!/usr/bin/env python3

import sys, argparse, nmap, glob, os
from socket import error as WrongIpException
from socket import inet_aton as check_ip
from lib.dr_buster import start_scan as dir_scan
from lib.exploit_db_wrapper import search, print_exploits
from threading import Thread
from time import sleep
from jinja2 import Template 

def parse_ip(ip):
    try:
        check_ip(ip)
    except WrongIpException:
        print("ip %s is not valid" % (ip,))
        sys.exit(1)
    return ip

def check_for_exploits(daemon, version=""):
    if version=="unknown":
        return None
    e = search(daemon + " " + version)
    if e:
        return e
    else:
        return None

def generate_report(exploits_list, running_services):
    paths = []
    for f in glob.glob("./lib/dr.buster.report*"):
        with open(f, 'r') as fi:
            paths.extend([line.split() for line in fi.readlines()])
    if len(paths) == 0:
        print("dr.buster didnt find any paths, so im not including dr.buster part in the report")
    
    found_exploits = False
    found_services = False
    if len(exploits_list) > 0:
        found_exploits = True 
    if len(running_services) > 0:
        found_services = True
    tmp = ""
    with open('./template.html', 'r') as f:
        tmp = '\n'.join(f.readlines())

    template = Template(tmp)
    html = template.render(
                found_services=found_services, 
                found_exploits=found_exploits, 
                running_services=running_services,
                daemon_exploits=exploits_list,
                paths=paths[:10]
            )

    with open('./dante_report.html', 'w') as f:
        f.write(html)
    print("Done, generated report in dante_report.html")

def start_scan(ip):
    exploits_for_report = []
    running_services = []
    dr_buster_started = False
    nm = nmap.PortScanner()
    print("Starting nmap")
    scan = None
    if input("Most common ports scan? [y/n]? ") in ['y','Y']:
        print("Ok scanning most common ports only")
        scan = nm.scan(hosts=ip, arguments="-T4 -sV --version-intensity=1 -p80")
    else:
        print("Ok scanning all ports, this will take some time..")
        scan = nm.scan(hosts=ip, arguments="-T4 -sV --version-intensity=1 -p-")
    
    result = scan['scan'][ip]['tcp']
    print("Done with scan, scanned totally %s ports" % (len(result),))
    for p in result:
        if result[p]['state'] == 'open' and result[p]['product'] != '':
            running_services.append([p, port['product']])
            port = result[p]
            daemon = port['product']
            version = port['version'] if port['version'] != "" else "unknown"
            print("Port %s is open and its running %s version %s" % (p, daemon, version))
            exploits = check_for_exploits(daemon, version)
            if exploits['verified'] or exploits['nverified']:
                exploits_for_report.append((daemon, exploits, p, result[p]['name'])) # name for http check later
            else:
                print("Didnt find any exploits for %s %s" % (daemon, version))
                if input("Do you want me to search for explots only for %s? [y/n] " % (daemon, )) in ["y","Y"]:
                    exploits = check_for_exploits(daemon)
                    if exploits['verified'] or exploits['nverified']:
                        print("Found %s exploits for %s!" % (len(exploits['verified']+exploits['nverified']), daemon))
                        exploits_for_report.append((daemon, exploits, p, result[p]['name']))
                    else:
                        print("No exploits for %s" % (daemon))
    WORDLIST = "" 
    if "http" in [x[3] for x in exploits_for_report]: # remember that "name for http check"? 
        WORDLIST = input("Found working HTTP server, please enter path to wordlist\n#> ")

    threads = []
    for d in exploits_for_report:
        if "http" in d[3]:
            print("Web server working on port %s, preparing dr.bust for it" % (d[2],))
            threads.append(Thread(dir_scan, args=("https://"+ip+":"+d[2], WORDLIST)))
    for t in threads:
        t.start()
        sleep(1.5) # sleep cause of dr.buster reports tied to timestamp
    for t in threads:
        t.join()

    generate_report(exploits_for_report, running_services)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("ip", help="IP address of server you want to test")
    if len(sys.argv) != 2:
        p.print_help()
        sys.exit(1)
    a = p.parse_args()
    if ':' in a:
        print("Provide an IP address without port.. il parse it myself")
        a = a.split(":")[0]
        print("Continuing with %s" % (a,))
    ip = parse_ip(a.ip)
    start_scan(ip)

if __name__ == '__main__':
    main()
else:
    print("This is not a module!")
    sys.exit(1)

