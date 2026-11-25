import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b1-router',
 'zone': 2,
 'title': 'Branch Office Edge',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['b1-files', 'b1-print', 'b1-cctv', 'b1-im', 'b1-hp-ssh', 'b1-hp-db'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['n2', 'nb1'],
 'gateway': {'ports': {'b1-files': 8000,
                       'b1-print': 8000,
                       'b1-cctv': 8000,
                       'b1-im': 8000,
                       'b1-hp-ssh': 8000,
                       'b1-hp-db': 8000},
             'issuer': 'l1-jump',
             'jump_aud': 'l1-jump',
             'jump_layer': 2,
             'next_layer': 2,
             'view': True,
             'view_targets': {'b1-files': {'flag': False, 'role': 'files', 'honeypot': False},
                              'b1-print': {'flag': False, 'role': 'print', 'honeypot': False},
                              'b1-cctv': {'flag': False, 'role': 'cctv', 'honeypot': False},
                              'b1-im': {'flag': True, 'role': 'im', 'honeypot': False},
                              'b1-hp-ssh': {'flag': False, 'role': 'ssh', 'honeypot': True},
                              'b1-hp-db': {'flag': False, 'role': 'db', 'honeypot': True}},
             'view_extra': ['b1-files', 'b1-print', 'b1-cctv', 'b1-hp-ssh', 'b1-hp-db']},
 'broker_key': '994a56141b64f6db3b790428be9b08c3'}

if __name__ == "__main__":
    serve(SPEC)
