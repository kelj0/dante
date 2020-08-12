import itertools, argparse
from socket import socket, gaierror, AF_INET, SOCK_STREAM
from ssl import wrap_socket, SSLError, PROTOCOL_TLSv1_2
from time import time
from datetime import datetime
from sys import exit, argv
from os.path import exists
from multiprocessing import cpu_count, Process

PROCESSES_COUNT = 32 if cpu_count() <= 4 else 64
WORD_LISTS = []
WORDLIST_PATH = ""
URL = ""
SSL_SUPPORTED = True
TIME = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
NOT_FOUND_CODE = 404

def get_code(host, port, path):
    global SSL_SUPPORTED
    s = socket(AF_INET, SOCK_STREAM)
    response = None
    if SSL_SUPPORTED:
        s = wrap_socket(s, ssl_version=PROTOCOL_TLSv1_2)
    try:
        s.connect((host, port))
    except (gaierror, TimeoutError):
        print("Name or service not known!")
        exit(1)
    except SSLError:
        print(
                "%s doesnt seem to support TLSv1. \nI'm trying http..."
                % ("https://"+ host + ":" + port + "/" + path, ))
        s = socket(AF_INET, SOCK_STREAM)
        try:
            s.connect((host, port))
        except Exception:
            print("Not working")
            exit(1)
        print("It worked.. I'm continuing with http requests")
        SSL_SUPPORTED = False
    except ConnectionRefusedError:
        print("Host seems down..")
        exit(1)

    request = "GET /%s HTTP/1.1\r\nHost:%s\r\n\r\n" % (path,host)
    s.send(request.encode())  
    response = s.recv(12)
    code = int(repr(response.decode()).split()[1].rstrip("'"))
    s.close()
    return code

def parse_url(url):
    global SSL_SUPPORTED, NOT_FOUND_CODE
    print("Validating url %s" % (url, ))
    host = None
    port = None
    path = ""
    if not url.endswith('/'):
        url+="/"
    try:
        if url.startswith("https"):
            url = url.split("//")[1]
            https = True
        elif url.startswith("http"):
            SSL_SUPPORTED = False
            url = url.split("//")[1]
        if ":" in url:
            host, port_path = url.split(":")
            port = int(port_path.split("/")[0])
        else:
            host = url.split("/")[0]
            port = 443 if https else 80
        path = '/'.join(url.split('/')[1:])
    except Exception:
        print("Cant parse url!")
        exit(1)

    print("Initial GET to see if host is up") 
    c = get_code(host, port, ".")
    print("[UP] => got %s" % (c,))
    print("Requesting path /aaaabbbb2 to set NOT_FOUND_CODE.")
    print("Some sites dont have 404 for not found, but rather retirect to the homepage if path doesnt exist")
    NOT_FOUND_CODE = get_code(host, port, "aaaabbbb2")
    print("NOT_FOUND_CODE is %s" % (NOT_FOUND_CODE,))
    return (host, port, path)

def prepare_wordlists(path):
    global WORD_LISTS
    lines = []
    print("Loading words from %s" % (path,))
    if exists(path):
        lines = [line.rstrip() for line in open(path)]
    else:
        print("ERR: wordlist not found!")
        exit(1)
    
    print("Loaded %s words" % (len(lines), ))
    words_per_process = int(len(lines)/PROCESSES_COUNT)
    start = 0
    print("Detected %s cores on this system, starting %s processes" % (cpu_count(), PROCESSES_COUNT ))
    print("Loading %s words per process" % (words_per_process, ))
    for p in range(PROCESSES_COUNT):
        if p == PROCESSES_COUNT - 1:
            WORD_LISTS.append(lines[start:])
        else:
            WORD_LISTS.append(lines[start:start+words_per_process])
        start+=words_per_process
        print("process %s ready, loaded %s words" % (p+1, len(WORD_LISTS[p])))

def scan_host(host, port, wordlist, process_id=None, path=""):
    for word in wordlist:
        code = get_code(host, port, path+word)
        if code != NOT_FOUND_CODE:
            print("%s:%s%s/%s returned [%s]!                \r" 
                    % ("http://"+host if not SSL_SUPPORTED else "https://"+host, port, path, word, code))
            finding = ("%s:%s%s/%s [%s]\n"
                    % ("http://"+host if not SSL_SUPPORTED else "https://"+host, port, path, word, code))
            write_to_report(finding)
        if process_id:
            print("PROCESS [%s] - scanning %s:%s/%s%s             \r" % (process_id, host, port, path, word), end="")
        else:
            print("Scanning %s:%s/%s%s             \r" % (host, port, path, word), end="")

def start_scan(url, wordlist_path):
    print("Starting scan on %s.." % (url,))
    host, port, path = parse_url(URL)
    prepare_wordlists(wordlist_path)
    procs = []
    for n, wordlist in enumerate(wordlist_path):
        procs.append(Process(target=scan_host, args=(host, port, wordlist, n+1, path)))
    for p in procs:
        p.start()
    for p in procs:
        p.join()

def write_to_report(finding):
    fname = "./dr.buster.report."+TIME
    with open(fname, "a") as f:
        f.write(finding)

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument("url", help="Url of web page you want to scan")
    p.add_argument("wordlist", help="Path to wordlist")
    if len(argv) != 3:
        p.print_help()
        exit(1)
    a = p.parse_args()
    URL=a.url
    WORDLIST_PATH=a.wordlist
    print("Starting Dr.buster..\nURL: %s \nWORDLIST: %s" % (URL, WORDLIST_PATH))
    start_time = time()
    start_scan(URL, WORDLIST_PATH)
    end_time = time()
    print()
    print("\nScanned %s paths in %s s." % (len(list(itertools.chain.from_iterable(WORD_LISTS))), end_time-start_time))


