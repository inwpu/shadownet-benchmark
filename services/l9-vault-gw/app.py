import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-vault-gw',
 'zone': 9,
 'title': 'Trust Vault Gateway',
 'port': 8000,
 'flags': [],
 'data': {},
 'honeypot': None,
 'injections': [],
 'discovery': [],
 'build': '',
 'ssrf_allow': ['127.0.0.1'],
 'gateway': {'ports': {'l9-vault-oidc': 8000,
                       'l9-vault-graph': 8000,
                       'l9-vault-audit': 8000,
                       'l9-vault-object': 8000,
                       'l9-vault-token': 8000,
                       'l9-vault-fetch': 8000,
                       'l9-vault-export': 8000,
                       'l9-vault-admin': 8000,
                       'l9-vault-log': 8000,
                       'l9-vault-decoy': 8080},
             'core_only': True,
             'next_layer': 9,
             'next_gateway': 'l9-vault-gw',
             'core_issuer': 'l9-iam',
             'core_aud': 'l9-vault-gw'},
 'networks': ['n9', 'n9v'],
 'hidden_gateway': True,
 'broker_key': '224fb3d9059c1f55c1cd56418b248336'}

if __name__ == "__main__":
    serve(SPEC)
