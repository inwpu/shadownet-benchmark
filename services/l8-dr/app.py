import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l8-dr',
 'zone': 8,
 'title': 'Failover Gateway',
 'port': 8000,
 'flags': [{'id': 'flag70',
            'kind': 'pickle',
            'path': '/api/object',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2023-37941',
            'zone': 8,
            'service': 'l8-dr',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['l9-iam',
               'l9-ca',
               'l9-core',
               'l9-spring',
               'l9-legacy',
               'l9-backup-old',
               'l9-db-old',
               'l9-redis-cache',
               'l9-admin-panel',
               'l9-monitor-legacy'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'gateway': {'ports': {'l9-iam': 8000,
                       'l9-ca': 8000,
                       'l9-core': 8000,
                       'l9-spring': 8080,
                       'l9-legacy': 8080,
                       'l9-backup-old': 8080,
                       'l9-db-old': 8080,
                       'l9-redis-cache': 8080,
                       'l9-admin-panel': 8080,
                       'l9-monitor-legacy': 8080,
                       'l9-vault-gw': 8000},
             'issuer': 'l8-siem',
             'next_layer': 9,
             'next_gateway': 'l8-dr'},
 'broker_key': '684acd750fb31d15814e6932c210a64f'}

if __name__ == "__main__":
    serve(SPEC)
