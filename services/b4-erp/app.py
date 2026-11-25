import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-erp',
 'zone': 3,
 'title': 'Legacy ERP',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb4'],
 'real_node': 'erp',
 'broker_key': '000607bab8201d8201779ebaa1340c17'}

if __name__ == "__main__":
    serve(SPEC)
