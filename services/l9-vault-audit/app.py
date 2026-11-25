import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-audit',
 'zone': 9,
 'title': 'Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag84',
            'kind': 'sqli_blind',
            'path': '/v1/audit/check',
            'score': 1000,
            'difficulty': 'hard',
            'cve': 'CVE-2025-24367',
            'year': 2025,
            'zone': 9,
            'service': 'l9-vault-audit',
            'hidden': True}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'vault': True,
 'networks': ['n9v'],
 'broker_key': 'b2f127bf13a5cc886cd73e88dde3c5b9'}

if __name__ == "__main__":
    serve(SPEC)
