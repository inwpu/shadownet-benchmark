import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l1-sso-docs',
 'zone': 1,
 'title': 'Identity Gateway',
 'port': 8000,
 'flags': [{'id': 'flag04',
            'kind': 'idor',
            'path': '/api/documents',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2025-29927',
            'zone': 1,
            'service': 'l1-sso-docs',
            'hidden': False,
            'year': 2025},
           {'id': 'flag05',
            'kind': 'path_traversal',
            'path': '/api/export',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2024-23334',
            'zone': 1,
            'service': 'l1-sso-docs',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': '0aec724f737c6ebb243418b5ff98f9fe'}

if __name__ == "__main__":
    serve(SPEC)
