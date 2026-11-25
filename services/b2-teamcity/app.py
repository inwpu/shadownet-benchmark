import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b2-teamcity',
 'zone': 6,
 'title': 'Pipeline Server',
 'port': 8000,
 'flags': [{'id': 'flag93',
            'kind': 'auth_bypass',
            'path': '/branch/console',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2024-27198',
            'year': 2024,
            'zone': 6,
            'service': 'b2-teamcity',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb2'],
 'challenge': {'kind': 'auth_bypass', 'salt': 'flag93-b2-teamcity'},
 'broker_key': 'ca9622eb75518b76374d0e49a411a5bf'}

if __name__ == "__main__":
    serve(SPEC)
