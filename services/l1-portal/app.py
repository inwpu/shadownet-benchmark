import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l1-portal',
 'zone': 1,
 'title': 'Meridian Corporate Portal',
 'port': 8000,
 'flags': [{'id': 'flag02',
            'kind': 'jwt_none',
            'path': '/api/admin',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2025-49001',
            'zone': 1,
            'service': 'l1-portal',
            'hidden': False,
            'year': 2025},
           {'id': 'flag03',
            'kind': 'ssrf',
            'path': '/api/proxy',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2024-28752',
            'zone': 1,
            'service': 'l1-portal',
            'hidden': False}],
 'data': {},
 'honeypot': {'path': '/admin/debug'},
 'injections': [],
 'discovery': ['l1-sso', 'l1-jump', 'l1-telnet', 'l1-sso-docs'],
 'build': '26.10.By:喜吾',
 'ssrf_allow': ['127.0.0.1', 'l1-'],
 'published': 8000,
 'ports': [(8000, 8000)],
 'broker_key': '7c31ed32497b7bac9c80f478037d82f1'}

if __name__ == "__main__":
    serve(SPEC)
