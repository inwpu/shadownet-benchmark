import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l7-hmi',
 'zone': 7,
 'title': 'Operator HMI',
 'port': 8000,
 'flags': [{'id': 'flag57',
            'kind': 'cmdi',
            'path': '/api/diag',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-46604',
            'zone': 7,
            'service': 'l7-hmi',
            'hidden': False}],
 'data': {},
 'honeypot': {'path': '/service/manual'},
 'injections': [],
 'discovery': ['l7-plc', 'l7-scada'],
 'build': '26.10.-Official',
 'ssrf_allow': ['127.0.0.1'],
 'collector': True,
 'broker_key': '3630e4a05f441249dbac38f9757625ea'}

if __name__ == "__main__":
    serve(SPEC)
