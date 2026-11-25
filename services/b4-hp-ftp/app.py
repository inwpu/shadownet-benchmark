import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-hp-ftp',
 'zone': 3,
 'title': 'Legacy File Transfer',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb4'],
 'mode': 'honeypot',
 'hp_profile': 'ftp',
 'hp_ports': [21, 22],
 'broker_key': '04690d1354fe9b3122e3cf9c02c4cb60'}

if __name__ == "__main__":
    serve(SPEC)
