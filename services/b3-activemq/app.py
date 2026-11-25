import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'b3-activemq',
 'zone': 5,
 'title': 'Message Broker',
 'port': 8000,
 'flags': [{'id': 'flag97',
            'kind': 'unauth_jmx',
            'path': '/branch/mq',
            'score': 700,
            'difficulty': 'hard',
            'cve': 'CVE-2024-32114',
            'year': 2024,
            'zone': 5,
            'service': 'b3-activemq',
            'hidden': False}],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'networks': ['nb3'],
 'challenge': {'kind': 'unauth_jmx', 'salt': 'flag97-b3-activemq'},
 'broker_key': '3cf6fae7a3ec5befa62eca2c99bd1e40'}

if __name__ == "__main__":
    serve(SPEC)
