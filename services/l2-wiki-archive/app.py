import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l2-wiki-archive',
 'zone': 2,
 'title': 'Knowledge Wiki Gateway',
 'port': 8000,
 'flags': [{'id': 'flag17',
            'kind': 'race',
            'path': '/api/coupon',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-42820',
            'zone': 2,
            'service': 'l2-wiki-archive',
            'hidden': False},
           {'id': 'flag18',
            'kind': 'zip_symlink',
            'path': '/archive',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2025-8110',
            'zone': 2,
            'service': 'l2-wiki-archive',
            'hidden': False,
            'year': 2025}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': 'af75bb31b5b36712a2570babe6d4494e'}

if __name__ == "__main__":
    serve(SPEC)
