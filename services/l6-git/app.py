import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, "/srv")

from shared.runtime import serve

SPEC = {'name': 'l6-git',
 'zone': 6,
 'title': 'Internal Git Service',
 'port': 8000,
 'flags': [{'id': 'flag46',
            'kind': 'trust_header',
            'path': '/internal/status',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-51467',
            'zone': 6,
            'service': 'l6-git',
            'hidden': False},
           {'id': 'flag47',
            'kind': 'log_injection',
            'path': '/audit',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-22527',
            'zone': 6,
            'service': 'l6-git',
            'hidden': False},
           {'id': 'flag48',
            'kind': 'state_write',
            'path': '/control',
            'score': 450,
            'difficulty': 'medium',
            'cve': 'CVE-2023-33246',
            'zone': 6,
            'service': 'l6-git',
            'hidden': False}],
 'data': {},
 'honeypot': {'path': '/admin/hooks'},
 'injections': [],
 'discovery': ['l6-ci', 'l6-registry', 'b2-router'],
 'build': '26.10.-WeChat',
 'ssrf_allow': ['127.0.0.1'],
 'branch': [{'name': 'b2-router', 'title': 'Branch operations edge'}],
 'broker_key': '9f34b177700c1f7ad4205d880ab47179'}

if __name__ == "__main__":
    serve(SPEC)
