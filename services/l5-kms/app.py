import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l5-kms',
 'zone': 5,
 'title': 'Key Management Gateway',
 'port': 8000,
 'flags': [{'id': 'flag43',
            'kind': 'pickle',
            'path': '/api/object',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-37941',
            'zone': 5,
            'service': 'l5-kms',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['l6-git',
               'l6-ci',
               'l6-registry',
               'l6-vite',
               'l6-legacy',
               'l6-backup-old',
               'l6-db-old',
               'l6-redis-cache',
               'l6-admin-panel',
               'l6-monitor-legacy',
               'b2-router'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'gateway': {'ports': {'l6-git': 8000,
                       'l6-ci': 8000,
                       'l6-registry': 8000,
                       'l6-vite': 5173,
                       'l6-legacy': 8080,
                       'l6-backup-old': 8080,
                       'l6-db-old': 8080,
                       'l6-redis-cache': 8080,
                       'l6-admin-panel': 8080,
                       'l6-monitor-legacy': 8080,
                       'b2-router': 8000},
             'issuer': 'l5-db',
             'next_layer': 6,
             'next_gateway': 'l5-kms'},
 'broker_key': '526d440d64afd40f42138c64c97aac60'}

if __name__ == "__main__":
    serve(SPEC)
