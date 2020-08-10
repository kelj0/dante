import sys, argparse, nmap
from socket import error as WrongIpException
from socket import inet_aton as check_ip
from lib.dr_buster import start_scan 
from lib.exploit_db_wrapper import search, print_exploits

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

def generate_report(report):
    for daemon, exploits in report:
        print("\nExploits for:\n%s\n" % (daemon, )) 
        print_exploits(exploits['verified'])
        print_exploits(exploits['nverified'])

def start_scan(ip):
    exploits_for_report = []
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
            port = result[p]
            daemon = port['product']
            version = port['version'] if port['version'] != "" else "unknown"
            print("Port %s is open and its running %s version %s" % (p, daemon, version))
            exploits = check_for_exploits(daemon, version)

            if exploits['verified'] or exploits['nverified']:
                exploits_for_report.append((daemon,exploits))
            else:
                print("Didnt find any exploits for %s %s" % (daemon, version))
                if input("Do you want me to search for explots only for %s?[y/n] " % (daemon, )) in ["y","Y"]:
                    exploits = check_for_exploits(daemon)
                    if exploits['verified'] or exploits['nverified']:
                        print("Found %s exploits for %s!" % (len(exploits['verified']+exploits['nverified']), daemon))
                        exploits_for_report.append((daemon,exploits))
                    else:
                        print("No exploits for %s" % (daemon))
    generate_report(exploits_for_report)

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
