import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b2-ingress',
 'zone': 6,
 'title': 'Cluster Ingress',
 'port': 8000,
 'flags': [{'id': 'flag94',
            'kind': 'admission_injection',
            'path': '/branch/admission',
            'score': 900,
            'difficulty': 'hard',
            'cve': 'CVE-2025-1974',
            'year': 2025,
            'zone': 6,
            'service': 'b2-ingress',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb2'],
 'challenge': {'kind': 'admission_injection', 'salt': 'flag94-b2-ingress'},
 'broker_key': '4cb05005756e5be15dfdc6b5d9478df0'}

if __name__ == "__main__":
    serve(SPEC)
