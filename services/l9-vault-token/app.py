import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-token',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag86',
            'kind': 'race',
            'path': '/v1/token/redeem',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2023-42820',
            'year': 2023,
            'zone': 9,
            'service': 'l9-vault-token',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': '141a421b6878632ad2db4a04c971a2ef'}

if __name__ == "__main__":
    serve(SPEC)
