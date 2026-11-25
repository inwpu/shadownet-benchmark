import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-grafana',
 'zone': 5,
 'title': 'Observability',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb3'],
 'real_node': 'grafana',
 'broker_key': '8a041e5b78f660ac84cbf5ea9983e480'}

if __name__ == "__main__":
    serve(SPEC)
