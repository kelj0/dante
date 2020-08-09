import sys, argparse, nmap
from dr_buster import start_scan 
from exploit_db_wrapper import search


EXPLOITS_FOR_REPORT = []

def parse_ip(ip):
    return ip

def check_for_exploits(daemon, version):
    if version=="unknown":
        return None
    e = search(daemon)
    if e:
        return e
    else:
        return None

def generate_report():
    pass

def start_scan(ip):
    global EXPLOITS_FOR_REPORT
    dr_buster_started = False
    nm = nmap.PortScanner()
    print("Starting nmap")
    scan = None
    if input("Most common ports scan? [y/n]") in ['y','Y']:
        print("Ok scanning most common ports only")
        scan = nm.scan(hosts=ip, arguments="-T4 -sV --version-intensity=1")
    else:
        print("Ok scanning all ports, this will take some time..")
        scan = nm.scan(hosts=ip, arguments="-T4 -sV --version-intensity=1 -p-")
    
    result = scan['scan'][ip]['tcp']
    print(result)
    print("Done with scan, scanned totally %s ports" % (len(result),))
    for p in result:
        if result[p]['state'] == 'open' and result[p][product] != '':
            port = result[p]
            daemon = port['product']
            version = port['version'] if port['version'] not "" else "unknown"
            print("Port %s is open and its running %s version %s" % (p, daemon, version))
            exploits = check_for_exploits(daemon, version)
            if exploits:
                EXPLOITS_FOR_REPORT.append({daemon:exploits})
            else:
                print("Didnt find any exploits for %" % (daemon,))
    generate_report()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("ip", help="IP address of server you want to test")
    if len(sys.argv) != 2:
        p.print_help()
        sys.exit(1)
    a = p.parse_args()
    ip = parse_ip(a.ip)
    start_scan(ip)

if __name__ == '__main__':
    main()
else:
    print("This is not a module!")
    sys.exit(1)
