import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b2-router',
 'zone': 6,
 'title': 'CI/CD Zone Edge',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['b2-jenkins',
               'b2-teamcity',
               'b2-ingress',
               'b2-gitlab',
               'b2-nexus',
               'b2-build',
               'b2-hp-api'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['n5', 'n6', 'nb2'],
 'gateway': {'ports': {'b2-jenkins': 8000,
                       'b2-teamcity': 8000,
                       'b2-ingress': 8000,
                       'b2-gitlab': 8000,
                       'b2-nexus': 8000,
                       'b2-build': 8000,
                       'b2-hp-api': 8000},
             'issuer': 'l5-db',
             'jump_aud': 'l5-kms',
             'jump_layer': 6,
             'next_layer': 6,
             'view': True,
             'view_targets': {'b2-jenkins': {'flag': True, 'role': 'jenkins', 'honeypot': False},
                              'b2-teamcity': {'flag': True, 'role': 'teamcity', 'honeypot': False},
                              'b2-ingress': {'flag': True, 'role': 'ingress', 'honeypot': False},
                              'b2-gitlab': {'flag': False, 'role': 'gitlab', 'honeypot': False},
                              'b2-nexus': {'flag': False, 'role': 'nexus', 'honeypot': False},
                              'b2-build': {'flag': False, 'role': 'build', 'honeypot': False},
                              'b2-hp-api': {'flag': False, 'role': 'api', 'honeypot': True}},
             'view_extra': ['b2-gitlab', 'b2-nexus', 'b2-build', 'b2-hp-api']},
 'broker_key': 'e5f0259c6055e37f1fd78d644727d193'}

if __name__ == "__main__":
    serve(SPEC)
