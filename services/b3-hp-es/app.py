import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-hp-es',
 'zone': 5,
 'title': 'Search Cluster',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb3'],
 'mode': 'honeypot',
 'hp_profile': 'es',
 'hp_ports': [9200, 6379],
 'broker_key': 'ba13ebfdb3880f5e2ec22dc9baa6038d'}

if __name__ == "__main__":
    serve(SPEC)
