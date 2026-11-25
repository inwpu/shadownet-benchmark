import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-hugegraph',
 'zone': 5,
 'title': 'Graph Database',
 'port': 8000,
 'flags': [{'id': 'flag98',
            'kind': 'groovy_injection',
            'path': '/branch/graph',
            'score': 700,
            'difficulty': 'hard',
            'cve': 'CVE-2024-27348',
            'year': 2024,
            'zone': 5,
            'service': 'b3-hugegraph',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb3'],
 'challenge': {'kind': 'groovy_injection', 'salt': 'flag98-b3-hugegraph'},
 'broker_key': '67deedb5b434bbc87f2ad871a084b7db'}

if __name__ == "__main__":
    serve(SPEC)
