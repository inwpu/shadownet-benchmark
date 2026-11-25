import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-chartbrew',
 'zone': 3,
 'title': 'Reporting Service',
 'port': 8000,
 'flags': [{'id': 'flag103',
            'kind': 'js_function_ctor',
            'path': '/branch/report',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2026-25887',
            'year': 2026,
            'zone': 3,
            'service': 'b4-chartbrew',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb4'],
 'challenge': {'kind': 'js_function_ctor', 'salt': 'flag103-b4-chartbrew'},
 'broker_key': 'd129874dffe2e39293eac2b5a92db3e8'}

if __name__ == "__main__":
    serve(SPEC)
