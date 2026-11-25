import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l2-wiki',
 'zone': 2,
 'title': 'Knowledge Wiki Gateway',
 'port': 8000,
 'flags': [{'id': 'flag16',
            'kind': 'pickle',
            'path': '/api/object',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2025-24813',
            'zone': 2,
            'service': 'l2-wiki',
            'hidden': False,
            'year': 2025}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['l3-api',
               'l3-files',
               'l3-mq',
               'l3-next',
               'l3-shop',
               'l3-legacy',
               'l3-backup-old',
               'l3-db-old',
               'l3-redis-cache',
               'l3-admin-panel',
               'l3-monitor-legacy',
               'b4-router'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'gateway': {'ports': {'l3-api': 8000,
                       'l3-files': 8000,
                       'l3-mq': 8000,
                       'l3-next': 3000,
                       'l3-shop': 5000,
                       'l3-legacy': 8080,
                       'l3-backup-old': 8080,
                       'l3-db-old': 8080,
                       'l3-redis-cache': 8080,
                       'l3-admin-panel': 8080,
                       'l3-monitor-legacy': 8080,
                       'b4-router': 8000},
             'issuer': 'l2-mail',
             'next_layer': 3,
             'next_gateway': 'l2-wiki'},
 'broker_key': '04e6ebcf5ab877aa09d1122058248b83'}

if __name__ == "__main__":
    serve(SPEC)
