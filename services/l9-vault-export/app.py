import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-export',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag88',
            'kind': 'path_traversal',
            'path': '/v1/export',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2025-41242',
            'year': 2025,
            'zone': 9,
            'service': 'l9-vault-export',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': '0fe0c2c3da439107b0cc360fa31f2469'}

if __name__ == "__main__":
    serve(SPEC)
