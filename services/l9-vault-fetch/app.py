import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-fetch',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag87',
            'kind': 'ssrf',
            'path': '/v1/fetch',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2024-45507',
            'year': 2024,
            'zone': 9,
            'service': 'l9-vault-fetch',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': 'ac674b70b3069fe051064ea9ccd70a79'}

if __name__ == "__main__":
    serve(SPEC)
