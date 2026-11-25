import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-hertzbeat',
 'zone': 5,
 'title': 'Monitoring Platform',
 'port': 8000,
 'flags': [{'id': 'flag96',
            'kind': 'yaml_deser',
            'path': '/branch/monitor',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2024-42323',
            'year': 2024,
            'zone': 5,
            'service': 'b3-hertzbeat',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb3'],
 'challenge': {'kind': 'yaml_deser', 'salt': 'flag96-b3-hertzbeat'},
 'broker_key': '3645afb1cd7162fed3d6025d78a8add8'}

if __name__ == "__main__":
    serve(SPEC)
