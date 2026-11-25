import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l5-kms-ops',
 'zone': 5,
 'title': 'Key Management Gateway',
 'port': 8000,
 'flags': [{'id': 'flag44',
            'kind': 'race',
            'path': '/api/coupon',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2023-42820',
            'zone': 5,
            'service': 'l5-kms-ops',
            'hidden': False},
           {'id': 'flag45',
            'kind': 'zip_symlink',
            'path': '/archive',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2023-37582',
            'zone': 5,
            'service': 'l5-kms-ops',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': 'd824daec6a86de65a80264c429d1e1be'}

if __name__ == "__main__":
    serve(SPEC)
