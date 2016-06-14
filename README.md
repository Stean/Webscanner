# Webscanner
This is a python3 script that not only searches for HTTP Servers, but also checks e.g. whether the corresponding server is a FRITZBox.

#### Requirements:
* nmap (will be used internally for port scanning)

#### Installation:
```
apt-get install nmap python3-requests python3-pip
pip3 install python-nmap
```

#### Usage:
Simply enter an nmap expression 

**Example:** ./webscan.py 1.2.3.4/24
