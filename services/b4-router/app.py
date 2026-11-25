import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b4-router',
 'zone': 3,
 'title': 'Legacy Business Edge',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['b4-php',
               'b4-tomcat',
               'b4-react',
               'b4-gotenberg',
               'b4-chartbrew',
               'b4-erp',
               'b4-hp-ftp'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['n2', 'n3', 'nb4'],
 'gateway': {'ports': {'b4-php': 8000,
                       'b4-tomcat': 8000,
                       'b4-react': 8000,
                       'b4-gotenberg': 8000,
                       'b4-chartbrew': 8000,
                       'b4-erp': 8000,
                       'b4-hp-ftp': 8000},
             'issuer': 'l2-mail',
             'jump_aud': 'l2-wiki',
             'jump_layer': 3,
             'next_layer': 3,
             'view': True,
             'view_targets': {'b4-php': {'flag': True, 'role': 'php', 'honeypot': False},
                              'b4-tomcat': {'flag': True, 'role': 'tomcat', 'honeypot': False},
                              'b4-react': {'flag': True, 'role': 'react', 'honeypot': False},
                              'b4-gotenberg': {'flag': True,
                                               'role': 'gotenberg',
                                               'honeypot': False},
                              'b4-chartbrew': {'flag': True,
                                               'role': 'chartbrew',
                                               'honeypot': False},
                              'b4-erp': {'flag': False, 'role': 'erp', 'honeypot': False},
                              'b4-hp-ftp': {'flag': False, 'role': 'ftp', 'honeypot': True}},
             'view_extra': ['b4-erp', 'b4-hp-ftp']},
 'broker_key': 'e379498e097b9c4a433f129c579cf180'}

if __name__ == "__main__":
    serve(SPEC)
