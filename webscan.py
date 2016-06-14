#!/usr/bin/env python3
import nmap
import requests
import sys

#Fix requests SSL warnings (http://stackoverflow.com/questions/32650984/why-does-python-requests-ignore-the-verify-parameter)
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ":RC4-SHA"

"""
Just a wrapper, which fixes an issue with the all_hosts listing
"""
class PortScannerFixed(nmap.PortScanner):
    def all_hosts(self):
        return self._scan_result["scan"].keys()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_usage():
    print("usage: webscan.py <nmap-Scan expression>")

#-------------------------------------------------
if __name__ == "__main__":
    if (len(sys.argv) < 2):
        print_usage()
        sys.exit(1)

    nm = PortScannerFixed()
    print("Scanning....")
    res = nm.scan(sys.argv[1], "80,443", "-sS --open")

    print("")
    for host in nm.all_hosts():
        print(host + ":")
        for service in res["scan"][host]["tcp"]:
            additional_info = ""
            schema = res["scan"][host]["tcp"][service]["name"]
            r = None

            try:
                r = requests.get(schema + "://" + host, verify=False)
            except requests.exceptions.ConnectionError:
                additional_info += bcolors.WARNING + " (HTTP(s)-Request failed)" + bcolors.ENDC
            except requests.exceptions.Timeout:
                additional_info += bcolors.WARNING + " (HTTP(s)-Request timeout)" + bcolors.ENDC
            except TypeError:
                additional_info += bcolors.WARNING + " (HTTP(s)-Request returned no content)" + bcolors.ENDC

            if (r !=None):
                if ("<title>FRITZ!Box</title>" in r.text):
                    additional_info += bcolors.FAIL + bcolors.BOLD + " -> FritzBox" + bcolors.ENDC
                else:
                    try:
                        if (r.headers["server"]!=None):
                            additional_info += " Server-Agent: '" + r.headers["server"] + "'"
                    except KeyError:
                        additional_info += " No server user-agent"
                    
            print("   -" + str(service) + additional_info)
