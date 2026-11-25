import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b1-files',
 'zone': 2,
 'title': 'Branch File Server',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb1'],
 'real_node': 'files',
 'broker_key': '03d278f2b658f9e8d9704866c8a293d5'}

if __name__ == "__main__":
    serve(SPEC)
