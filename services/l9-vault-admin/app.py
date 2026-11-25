import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-admin',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag89',
            'kind': 'jwt_none',
            'path': '/v1/admin/token',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2025-49001',
            'year': 2025,
            'zone': 9,
            'service': 'l9-vault-admin',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': 'c161f77261b70b1d7b21ac78be1297a7'}

if __name__ == "__main__":
    serve(SPEC)
