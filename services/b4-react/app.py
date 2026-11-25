import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-react',
 'zone': 3,
 'title': 'Partner Frontend',
 'port': 8000,
 'flags': [{'id': 'flag101',
            'kind': 'flight_deser',
            'path': '/branch/app',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2025-55182',
            'year': 2025,
            'zone': 3,
            'service': 'b4-react',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb4'],
 'challenge': {'kind': 'flight_deser', 'salt': 'flag101-b4-react'},
 'broker_key': '313d43ffbc58a04cdc93e6edea68f1f0'}

if __name__ == "__main__":
    serve(SPEC)
