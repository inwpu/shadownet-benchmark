import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b1-im',
 'zone': 2,
 'title': 'AI Operations Gateway',
 'port': 8000,
 'flags': [{'id': 'flag91',
            'kind': 'csrft_websocket',
            'path': '/branch/ui',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2026-25253',
            'year': 2026,
            'zone': 2,
            'service': 'b1-im',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb1'],
 'challenge': {'kind': 'csrft_websocket', 'salt': 'flag91-b1-im'},
 'broker_key': 'f13d23dfad42e26fedf9410bd5bfff7f'}

if __name__ == "__main__":
    serve(SPEC)
