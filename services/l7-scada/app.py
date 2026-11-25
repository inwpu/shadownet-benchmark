import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l7-scada',
 'zone': 7,
 'title': 'SCADA Gateway',
 'port': 8000,
 'flags': [{'id': 'flag62',
            'kind': 'sqli_blind',
            'path': '/api/check',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2023-39361',
            'zone': 7,
            'service': 'l7-scada',
            'hidden': False},
           {'id': 'flag63',
            'kind': 'jwt_kid',
            'path': '/api/operator',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2024-43441',
            'zone': 7,
            'service': 'l7-scada',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['l8-siem',
               'l8-backup',
               'l8-dr',
               'l8-nginx-ui',
               'l8-legacy',
               'l8-backup-old',
               'l8-db-old',
               'l8-redis-cache',
               'l8-admin-panel',
               'l8-monitor-legacy',
               'l8-dr-archive'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'gateway': {'ports': {'l8-siem': 8000,
                       'l8-backup': 8000,
                       'l8-dr': 8000,
                       'l8-nginx-ui': 9000,
                       'l8-legacy': 8080,
                       'l8-backup-old': 8080,
                       'l8-db-old': 8080,
                       'l8-redis-cache': 8080,
                       'l8-admin-panel': 8080,
                       'l8-monitor-legacy': 8080,
                       'l8-dr-archive': 8000},
             'issuer': 'l7-plc',
             'next_layer': 8,
             'next_gateway': 'l7-scada'},
 'broker_key': '693fb3e8d4b1dc68826cf40aa3045213'}

if __name__ == "__main__":
    serve(SPEC)
