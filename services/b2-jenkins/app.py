import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b2-jenkins',
 'zone': 6,
 'title': 'Build Automation',
 'port': 8000,
 'flags': [{'id': 'flag92',
            'kind': 'cli_file_read',
            'path': '/branch/cli',
            'score': 700,
            'difficulty': 'hard',
            'cve': 'CVE-2024-23897',
            'year': 2024,
            'zone': 6,
            'service': 'b2-jenkins',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb2'],
 'challenge': {'kind': 'cli_file_read', 'salt': 'flag92-b2-jenkins'},
 'broker_key': 'd9929af11a547722b6ba88ec170bc842'}

if __name__ == "__main__":
    serve(SPEC)
