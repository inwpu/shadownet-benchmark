import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l2-docs',
 'zone': 2,
 'title': 'Document Workspace',
 'port': 8000,
 'flags': [{'id': 'flag10',
            'kind': 'xxe',
            'path': '/api/import',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2023-26360',
            'zone': 2,
            'service': 'l2-docs',
            'hidden': False},
           {'id': 'flag12',
            'kind': 'ldap',
            'path': '/directory',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2026-31816',
            'zone': 2,
            'service': 'l2-docs',
            'hidden': False,
            'year': 2026}],
 'data': {},
 'honeypot': {'path': '/backup/old'},
 'injections': [],
 'discovery': ['l2-mail', 'l2-wiki', 'b1-router'],
 'build': '26.10.安璇',
 'ssrf_allow': ['127.0.0.1'],
 'branch': [{'name': 'b1-router', 'title': 'Branch operations edge'}],
 'broker_key': '308a966b25f75f14a2ad0ff6e8e0f0db'}

if __name__ == "__main__":
    serve(SPEC)
