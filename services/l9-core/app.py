import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-core',
 'zone': 9,
 'title': 'Core Trust Vault',
 'port': 8000,
 'flags': [{'id': 'flag79',
            'kind': 'exposed_backup',
            'path': '/backup',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2026-27944',
            'zone': 9,
            'service': 'l9-core',
            'hidden': False,
            'year': 2026},
           {'id': 'flag80',
            'kind': 'db_link',
            'path': '/linked',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2025-24367',
            'zone': 9,
            'service': 'l9-core',
            'hidden': False,
            'year': 2025}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'broker_key': '5d68c79aa2020d342eebe7099eeabef5'}

if __name__ == "__main__":
    serve(SPEC)
