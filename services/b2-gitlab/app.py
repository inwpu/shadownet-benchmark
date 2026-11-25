import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b2-gitlab',
 'zone': 6,
 'title': 'Source Control',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb2'],
 'real_node': 'gitlab',
 'broker_key': '44f311c31c83e4b2439985a84abdc18e'}

if __name__ == "__main__":
    serve(SPEC)
