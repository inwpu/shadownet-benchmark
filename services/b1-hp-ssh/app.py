import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b1-hp-ssh',
 'zone': 2,
 'title': 'Legacy Remote Shell',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb1'],
 'mode': 'honeypot',
 'hp_profile': 'ssh',
 'hp_ports': [22, 80, 443, 8080],
 'broker_key': '4e9cbad7291f575d9f24e64ab6c2f3b1'}

if __name__ == "__main__":
    serve(SPEC)
