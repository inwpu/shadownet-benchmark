import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l9-iam',
 'zone': 9,
 'title': 'Core IAM',
 'port': 8000,
 'flags': [{'id': 'flag73',
            'kind': 'trust_header',
            'path': '/internal/status',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-51467',
            'zone': 9,
            'service': 'l9-iam',
            'hidden': False},
           {'id': 'flag74',
            'kind': 'log_injection',
            'path': '/audit',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2023-22527',
            'zone': 9,
            'service': 'l9-iam',
            'hidden': False},
           {'id': 'flag75',
            'kind': 'state_write',
            'path': '/control',
            'score': 800,
            'difficulty': 'hard',
            'cve': 'CVE-2023-33246',
            'zone': 9,
            'service': 'l9-iam',
            'hidden': False}],
 'data': {},
 'honeypot': {'path': '/root/keys'},
 'injections': [],
 'discovery': ['l9-ca', 'l9-core'],
 'build': '26.10.攻防SRC',
 'ssrf_allow': ['127.0.0.1'],
 'core_issuer': True,
 'core_flag': 'flag73',
 'core_aud': 'l9-vault-gw',
 'broker_key': '1f81bcc9dfe8918c21a4985df7207e4e'}

if __name__ == "__main__":
    serve(SPEC)
