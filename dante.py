import sys, argparse
from dr_buster import start_scan 
from exploit_db_wrapper import search


EXPLOITS_FOR_REPORT = []

def parse_ip(ip):
    pass

def check_for_exploits(daemon):
    e = search(daemon)
    if e:
        return e
    else:
        return None

def generate_report():
    pass

def start_scan(ip):
    dr_buster_started = False
    for p in nmap.scanports():
        if p.open():
            exploits = check_for_exploits(p.info())
            if exploits:
                EXPLOITS_FOR_REPORT.append({p.info():exploits}
        if p.open() and ((p.number==80 or p.number==443) and not dr_buster_started):
            dr_buster_started = True
            new_thread(start_scan("https://"+ip, wordlist_path))
    generate_report()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("ip", help="IP address of server you want to test")
    if len(sys.argv) != 2:
        p.print_help()
        sys.exit(1)

    ip = parse_ip(p.ip)
    start_scan(ip)

if __name__ == '__main__':
    main()
else:
    print("This is not a module!")
    sys.exit(1)
