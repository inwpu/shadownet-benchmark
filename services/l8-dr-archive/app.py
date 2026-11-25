import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l8-dr-archive',
 'zone': 8,
 'title': 'Failover Gateway',
 'port': 8000,
 'flags': [{'id': 'flag72',
            'kind': 'zip_symlink',
            'path': '/archive',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2023-37582',
            'zone': 8,
            'service': 'l8-dr-archive',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': 'db6151401cdefccaf083072a069e1811'}

if __name__ == "__main__":
    serve(SPEC)
