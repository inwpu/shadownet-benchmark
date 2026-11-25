import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l4-bastion',
 'zone': 4,
 'title': 'Operations Bastion',
 'port': 8000,
 'flags': [{'id': 'flag28',
            'kind': 'sqli_union',
            'path': '/api/search',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2023-25157',
            'zone': 4,
            'service': 'l4-bastion',
            'hidden': False},
           {'id': 'flag29',
            'kind': 'path_traversal',
            'path': '/api/export',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2024-23334',
            'zone': 4,
            'service': 'l4-bastion',
            'hidden': False},
           {'id': 'flag30',
            'kind': 'idor',
            'path': '/api/documents',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2023-23752',
            'zone': 4,
            'service': 'l4-bastion',
            'hidden': False}],
 'data': {},
 'honeypot': {'path': '/api/legacy'},
 'injections': [],
 'discovery': ['l4-monitor', 'l4-scheduler'],
 'build': '26.10.cat_',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': '3cbb5692e84f841dc005799540cd257e'}

if __name__ == "__main__":
    serve(SPEC)
