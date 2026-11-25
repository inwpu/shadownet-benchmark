import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l3-api',
 'zone': 3,
 'title': 'Business API',
 'port': 8000,
 'flags': [{'id': 'flag20',
            'kind': 'log_injection',
            'path': '/audit',
            'score': 200,
            'difficulty': 'easy',
            'cve': 'CVE-2026-22777',
            'zone': 3,
            'service': 'l3-api',
            'hidden': False,
            'year': 2026}],
 'data': {},
 'honeypot': {'path': '/internal/metrics'},
 'injections': [],
 'discovery': ['l3-files', 'l3-mq'],
 'build': '26.10.-nwpu',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': '5c4e4892a3a94235b79d2b193b59db74'}

if __name__ == "__main__":
    serve(SPEC)
