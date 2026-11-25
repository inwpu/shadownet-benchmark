import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-log',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag90',
            'kind': 'log_injection',
            'path': '/v1/audit/log',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2023-22527',
            'year': 2023,
            'zone': 9,
            'service': 'l9-vault-log',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': 'f2008ded54c102a13cabe4e492e595bc'}

if __name__ == "__main__":
    serve(SPEC)
