import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l8-siem',
 'zone': 8,
 'title': 'Security Operations SIEM',
 'port': 8000,
 'flags': [{'id': 'flag64',
            'kind': 'hardcoded_secret',
            'path': '/api/console',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2025-49001',
            'zone': 8,
            'service': 'l8-siem',
            'hidden': False,
            'year': 2025},
           {'id': 'flag65',
            'kind': 'mass_assignment',
            'path': '/api/profile',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-22515',
            'zone': 8,
            'service': 'l8-siem',
            'hidden': False},
           {'id': 'flag66',
            'kind': 'xxe',
            'path': '/api/import',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-26360',
            'zone': 8,
            'service': 'l8-siem',
            'hidden': False}],
 'data': {},
 'honeypot': {'path': '/api/export'},
 'injections': [],
 'discovery': ['l8-backup', 'l8-dr'],
 'build': '26.10._Account:',
 'ssrf_allow': ['127.0.0.1'],
 'reveal_flag': 'flag66',
 'reveal_aud': 'l8-dr',
 'reveal_layer': 9,
 'broker_key': 'e37405e8da169a68b465b7c424f076fe'}

if __name__ == "__main__":
    serve(SPEC)
