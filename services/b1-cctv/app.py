import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b1-cctv',
 'zone': 2,
 'title': 'Branch CCTV NVR',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb1'],
 'real_node': 'cctv',
 'broker_key': '60cf37594ba43070c6ccc33307bf7b4f'}

if __name__ == "__main__":
    serve(SPEC)
