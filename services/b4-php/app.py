import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-php',
 'zone': 3,
 'title': 'Legacy Portal',
 'port': 8000,
 'flags': [{'id': 'flag99',
            'kind': 'filter_chain',
            'path': '/branch/legacy',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2024-2961',
            'year': 2024,
            'zone': 3,
            'service': 'b4-php',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb4'],
 'challenge': {'kind': 'filter_chain', 'salt': 'flag99-b4-php'},
 'broker_key': '897f3bb986ec6e27fe5029eeeb752f11'}

if __name__ == "__main__":
    serve(SPEC)
