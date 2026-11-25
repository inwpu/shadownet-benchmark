import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b1-hp-db',
 'zone': 2,
 'title': 'Legacy Database',
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
 'hp_profile': 'db',
 'hp_ports': [3306, 6379],
 'broker_key': 'dfe17ad385c4b52bd3983c8e67f0ba55'}

if __name__ == "__main__":
    serve(SPEC)
