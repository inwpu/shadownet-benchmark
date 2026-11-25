import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-warehouse',
 'zone': 5,
 'title': 'Analytics Warehouse',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb3'],
 'real_node': 'warehouse',
 'broker_key': '870b7d3852046b73a100333682f260ea'}

if __name__ == "__main__":
    serve(SPEC)
