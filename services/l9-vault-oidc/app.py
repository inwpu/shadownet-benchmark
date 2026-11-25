import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-oidc',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag82',
            'kind': 'jwt_kid',
            'path': '/v1/oidc/token',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2024-43441',
            'year': 2024,
            'zone': 9,
            'service': 'l9-vault-oidc',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': '32a916725524ff22bf5d4ca8e73a78d5'}

if __name__ == "__main__":
    serve(SPEC)
