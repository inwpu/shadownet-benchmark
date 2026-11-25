import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b1-print',
 'zone': 2,
 'title': 'Branch Print Server',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb1'],
 'real_node': 'print',
 'broker_key': '1b7cb1d9c86acf54ff1e33c5d484b6d2'}

if __name__ == "__main__":
    serve(SPEC)
