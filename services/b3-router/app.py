import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-router',
 'zone': 5,
 'title': 'Data Platform Edge',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': ['b3-geoserver',
               'b3-hertzbeat',
               'b3-activemq',
               'b3-hugegraph',
               'b3-grafana',
               'b3-warehouse',
               'b3-hp-es'],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['n5', 'nb3'],
 'gateway': {'ports': {'b3-geoserver': 8000,
                       'b3-hertzbeat': 8000,
                       'b3-activemq': 8000,
                       'b3-hugegraph': 8000,
                       'b3-grafana': 8000,
                       'b3-warehouse': 8000,
                       'b3-hp-es': 8000},
             'issuer': 'l4-scheduler',
             'jump_aud': 'l4-scheduler',
             'jump_layer': 5,
             'next_layer': 5,
             'view': True,
             'view_targets': {'b3-geoserver': {'flag': True,
                                               'role': 'geoserver',
                                               'honeypot': False},
                              'b3-hertzbeat': {'flag': True,
                                               'role': 'hertzbeat',
                                               'honeypot': False},
                              'b3-activemq': {'flag': True, 'role': 'activemq', 'honeypot': False},
                              'b3-hugegraph': {'flag': True,
                                               'role': 'hugegraph',
                                               'honeypot': False},
                              'b3-grafana': {'flag': False, 'role': 'grafana', 'honeypot': False},
                              'b3-warehouse': {'flag': False,
                                               'role': 'warehouse',
                                               'honeypot': False},
                              'b3-hp-es': {'flag': False, 'role': 'es', 'honeypot': True}},
             'view_extra': ['b3-grafana', 'b3-warehouse', 'b3-hp-es']},
 'broker_key': 'abf5c67d55b874f51d4537524d2759d2'}

if __name__ == "__main__":
    serve(SPEC)
