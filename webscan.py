#!/usr/bin/env python3
import nmap
import requests
import sys

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
                    if (r.headers["server"]!=None):
                        additional_info += " Server-Agent: '" + r.headers["server"] + "'"
                    
            print("   -" + str(service) + additional_info)
