import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-graph',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag83',
            'kind': 'graphql',
            'path': '/v1/graph',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2023-22515',
            'year': 2023,
            'zone': 9,
            'service': 'l9-vault-graph',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': '3c9a3017a999fc518178830f68312abc'}

if __name__ == "__main__":
    serve(SPEC)
