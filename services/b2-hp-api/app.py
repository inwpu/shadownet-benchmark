import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b2-hp-api',
 'zone': 6,
 'title': 'Pipeline API',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb2'],
 'mode': 'honeypot',
 'hp_profile': 'api',
 'hp_ports': [80, 443, 8080],
 'broker_key': 'cb9b52743e44064c0ebbedaec1b70a61'}

if __name__ == "__main__":
    serve(SPEC)
