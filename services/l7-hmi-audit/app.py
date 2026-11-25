import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l7-hmi-audit',
 'zone': 7,
 'title': 'Operator HMI',
 'port': 8000,
 'flags': [{'id': 'flag55',
            'kind': 'sqli_union',
            'path': '/api/search',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2025-24367',
            'zone': 7,
            'service': 'l7-hmi-audit',
            'hidden': False,
            'year': 2025},
           {'id': 'flag56',
            'kind': 'path_traversal',
            'path': '/api/export',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2024-23334',
            'zone': 7,
            'service': 'l7-hmi-audit',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': 'ddf14e8a621d4516df816fcb05f32383'}

if __name__ == "__main__":
    serve(SPEC)
