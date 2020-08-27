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
        version = ""
    e = search(daemon + " " + version)
    if e:
        return e
    else:
        return {'verified':None,'nverified':None}

def generate_report(exploits_list, running_services, web_scan):
    paths = []
    if web_scan:
        for f in glob.glob("./dr.buster.report*"):
            with open(f, 'r') as fi:
                paths.extend([line.split() for line in fi.readlines()])
            os.remove(f)
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
                web_scan=web_scan,
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
        scan = nm.scan(hosts=ip, arguments="-T4 -sV --version-intensity=1")
    else:
        print("Ok scanning all ports, this will take some time..")
        scan = nm.scan(hosts=ip, arguments="-T4 -sV --version-intensity=1 -p-")
    
    result = scan['scan'][ip]['tcp']
    print("Done with scan, %s port up" % (len(result),))
    for p in result:
        if result[p]['state'] == 'open' and result[p]['name'] != '':
            port = result[p]
            service_name = ""
            web_server = False
            if port['name'] == 'http':
                service_name = port['product']
                web_server = True
            else:
                service_name = port['name']
            port_number = p
            service_version = port['version'] if port['version'] != "" else "unknown"

            running_services.append([port_number, service_name])
            print("Port %s is open and its running %s version %s" % (port_number, service_name, service_version))
            exploits = check_for_exploits(service_name, service_version)
            if not exploits['verified'] or not exploits['nverified']:
                print("Didnt find any exploits for %s %s" % (service_name, service_version))
                try:
                    versions = service_version.split('.')
                    print("But I can search for only part of versions, eg. if version is 4.5.6.1 I will search for 4.5.6 or 4.5")
                    if input("Do you want me to search for that? [y/n] ") in ["y","Y"]:
                        for i in range(len(versions)):
                            s = '.'.join(versions[:len(versions)-i-1])
                            print("Searching for %s %s" % (service_name, s))
                            exploits = check_for_exploits(service_name, s)
                            if exploits['verified'] or exploits['nverified']:
                                print("Found %s exploits for %s!" % (len(exploits['verified']+exploits['nverified']), service_name))
                                exploits_for_report.append((service_name, exploits, port_number, web_server))
                                break
                            else:
                                print("No exploits for %s" % (service_name))
                except Exception:
                    continue
            else:
                print("Found %s exploits for %s!" % (len(exploits['verified']+exploits['nverified']), service_name))
                exploits_for_report.append((service_name, exploits, port_number, web_server))

    WORDLIST = "" 
    if any([x[3] for x in exploits_for_report]): # remember that "name for http check"? 
        WORDLIST = input("Found working HTTP server, please enter path to wordlist\n#> ")
    else:
        print("Didnt find any HTTP servers..")
    threads = []
    for d in exploits_for_report:
        if d[3]: # web_server
            print("Web server working on port %s, preparing dr.bust for it" % (d[2],))
            threads.append(Thread(target=dir_scan, args=(str(ip)+":"+str(d[2]), WORDLIST)))
    for t in threads:
        t.start()
        sleep(1.5) # sleep cause of dr.buster reports tied to timestamp
    for t in threads:
        t.join()

    generate_report(exploits_for_report, running_services, web_server)


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

