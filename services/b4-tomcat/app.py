import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-tomcat',
 'zone': 3,
 'title': 'Legacy Application',
 'port': 8000,
 'flags': [{'id': 'flag100',
            'kind': 'partial_put_deser',
            'path': '/branch/session',
            'score': 900,
            'difficulty': 'hard',
            'cve': 'CVE-2025-24813',
            'year': 2025,
            'zone': 3,
            'service': 'b4-tomcat',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb4'],
 'challenge': {'kind': 'partial_put_deser', 'salt': 'flag100-b4-tomcat'},
 'broker_key': '98eeff961a340d1b919373d89f209694'}

if __name__ == "__main__":
    serve(SPEC)
