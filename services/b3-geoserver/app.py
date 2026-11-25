import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-geoserver',
 'zone': 5,
 'title': 'GIS Service',
 'port': 8000,
 'flags': [{'id': 'flag95',
            'kind': 'xpath_injection',
            'path': '/branch/ows',
            'score': 700,
            'difficulty': 'hard',
            'cve': 'CVE-2024-36401',
            'year': 2024,
            'zone': 5,
            'service': 'b3-geoserver',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb3'],
 'challenge': {'kind': 'xpath_injection', 'salt': 'flag95-b3-geoserver'},
 'broker_key': '5012361b9679461dc2cefddeeda01046'}

if __name__ == "__main__":
    serve(SPEC)
