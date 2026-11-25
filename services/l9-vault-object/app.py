import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-object',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag85',
            'kind': 'pickle',
            'path': '/v1/object/load',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2023-37941',
            'year': 2023,
            'zone': 9,
            'service': 'l9-vault-object',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': '37cf895c4813c0f8ef1070ba064602ca'}

if __name__ == "__main__":
    serve(SPEC)
