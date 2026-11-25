import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-gotenberg',
 'zone': 3,
 'title': 'Document Service',
 'port': 8000,
 'flags': [{'id': 'flag102',
            'kind': 'exiftool_arg_injection',
            'path': '/branch/docs',
            'score': 700,
            'difficulty': 'hard',
            'cve': 'CVE-2026-40281',
            'year': 2026,
            'zone': 3,
            'service': 'b4-gotenberg',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb4'],
 'challenge': {'kind': 'exiftool_arg_injection', 'salt': 'flag102-b4-gotenberg'},
 'broker_key': '0766e75fb64c7f93fded5231bf2ceae3'}

if __name__ == "__main__":
    serve(SPEC)
