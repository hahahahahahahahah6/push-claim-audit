import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from push_claim_audit.audit import audit, claims, evidence, normalize, pattern, PUSH, NOPUSH
from push_claim_audit.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
WEB = 'from pywebpush import webpush\nwebpush()'


class AuditTests(unittest.TestCase):
    def fixture(self, readme='push notifications', files=None):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for name, text in dict({'README.md': readme}, **(files or {})).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8')
        return root

    def cli(self, root, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main([str(root), *args])
        return code, out.getvalue()

    def check_case(self, source, good):
        root = self.fixture(files={'app.py': source})
        code, output = self.cli(root, '--json')
        result = json.loads(output)
        self.assertEqual(code, 0 if good else 2)
        self.assertEqual(result['verdict'], 'PASS' if good else 'FAIL')
        self.assertEqual(result['findings'], [] if good else [dict(rule='documented-push-claim-false', severity='HIGH', message='Documented device delivery lacks production send evidence.')])

    def test_no_push(self):
        root = self.fixture('no push support', {'app.py': WEB})
        code, text = self.cli(root, '--json')
        self.assertEqual(code, 2)
        self.assertEqual([(f['rule'], f['severity']) for f in json.loads(text)['findings']], [('documented-no-push-claim-false', 'HIGH')])

    def test_exclusions(self):
        for phrase in ('ordinary application', 'the push chapter explains delivery', 'sms notifications', 'email notifications', 'webhook', 'websocket server', 'server-sent events', 'GraphQL interface', 'gRPC interface', 'MQTT'):
            with self.subTest(phrase=phrase):
                root = self.fixture(phrase, {'app.py': WEB})
                self.assertEqual(audit(root)['claims'], [])
                self.assertEqual(self.cli(root)[0], 0)

    def test_no_source(self):
        self.assertEqual(self.cli(self.fixture())[0], 2)
        self.assertEqual(self.cli(self.fixture('no push support'))[0], 0)

    def test_test_only(self):
        for path in ('tests/send.py', 'test_send.py', 'send_test.py'):
            root = self.fixture(files={path: WEB})
            self.assertEqual(audit(root)['findings'][0]['severity'], 'MEDIUM')
            self.assertEqual(self.cli(root)[0], 0)
            self.assertEqual(self.cli(root, '--fail-on', 'MEDIUM')[0], 2)

    def test_fences_and_inline(self):
        for fence in ('```', '~~~~'):
            self.assertEqual(claims(fence + '\npush notifications\n' + fence), (False, False))
        self.assertEqual(self.cli(self.fixture('inline `push notifications`'))[0], 2)

    def test_negation(self):
        self.assertEqual(claims('does not send push'), (False, True))
        self.assertEqual(claims("doesn't send push"), (False, True))
        for phrase in NOPUSH:
            self.assertEqual(claims(phrase), (False, True), phrase)
        for phrase in PUSH:
            self.assertEqual(claims(phrase), (True, False), phrase)

    def test_normalization_and_boundaries(self):
        self.assertEqual(claims('PUSH-\nnotifications'), (True, False))
        self.assertEqual(claims('push\n\nnotifications'), (False, False))
        self.assertEqual(claims('repush notificationsXYZ'), (False, False))

    def test_module_boundary(self):
        root = self.fixture(files={'a.py': 'from firebase_admin.messaging import Message\nm=Message()', 'b.py': 'from firebase_admin.messaging import send\nsend(m)'})
        self.assertEqual(self.cli(root)[0], 2)
        root = self.fixture(files={'a.py': 'from apns2 import APNsClient\nclient=APNsClient()', 'b.py': 'client.send_notification()'})
        self.assertEqual(self.cli(root)[0], 2)

    def test_self_audit(self):
        result = audit(ROOT)
        self.assertEqual(result['verdict'], 'PASS')
        self.assertEqual(result['claims'], [])
        self.assertEqual(result['findings'], [])
        for path in ROOT.rglob('*.md'):
            if path == ROOT / 'README.md' or 'docs' in path.relative_to(ROOT).parts:
                text = normalize(path.read_text())
                self.assertIsNone(pattern(PUSH + NOPUSH).search(text), str(path))

    def test_cli_surface(self):
        root = self.fixture(files={'app.py': WEB, 'docs/guide.md': 'no push support'})
        self.assertEqual(self.cli(root)[0], 2)
        self.assertEqual(self.cli(root, '--ignore', 'docs/*')[0], 0)
        code, text = self.cli(root, '--verbose')
        self.assertIn('app.py', text)
        self.assertEqual(self.cli(root / 'missing')[0], 1)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main([])
        self.assertEqual(exc.exception.code, 1)
        version = subprocess.run([sys.executable, '-m', 'push_claim_audit', '--version'], capture_output=True, text=True)
        self.assertEqual((version.returncode, version.stdout.strip()), (0, '0.1.0'))

    def test_env_guard(self):
        original = Path.open
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, '.env')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', guarded):
            self.assertEqual(audit(ROOT)['verdict'], 'PASS')
        self.assertTrue((ROOT / 'tests/fixtures/.env').is_file())

    def test_packaging_conventions(self):
        for path in list(ROOT.rglob('*.py')) + [ROOT / 'README.md', ROOT / 'pyproject.toml']:
            if any(p in {'build', 'dist', '.venv'} for p in path.parts):
                continue
            # Match a command token rather than prose language names.
            self.assertIsNone(re.search(r'\bpy' + r'thon\s+(?:-m|-c|[^\s]+\.py)', path.read_text()), str(path))
        config = (ROOT / 'pyproject.toml').read_text()
        self.assertIn('setuptools>=77', config)
        self.assertIn('license = "MIT"', config)
        self.assertIn('recursive-include tests', (ROOT / 'MANIFEST.in').read_text())

    def test_excluded_source_and_symlinks(self):
        for name in ('fixtures/a.py', 'docs/a.py', 'examples/a.py'):
            self.assertEqual(self.cli(self.fixture(files={name: WEB}))[0], 2)
        root = self.fixture(files={'fixtures/real.py': WEB})
        (root / 'linked.py').symlink_to(root / 'fixtures/real.py')
        self.assertEqual(self.cli(root)[0], 2)

    def test_negative_test_docs_asymmetry(self):
        root = self.fixture('neutral', {'app.py': WEB, 'tests/docs/readme.md': 'no push support'})
        self.assertEqual(self.cli(root)[0], 2)

    def test_both_families(self):
        root = self.fixture('push notifications. no push support')
        self.assertEqual(len(audit(root)['findings']), 1)


GOOD = [
'from firebase_admin.messaging import Message, send\nm=Message()\nsend(m)',
'import firebase_admin.messaging as fm\nm=fm.Message()\nfm.send(m)',
'import firebase_admin\nm=firebase_admin.messaging.Message()\nfirebase_admin.messaging.send(m)',
'from firebase_admin.messaging import Message as FCMMessage, send as fcm_send\nm=FCMMessage()\nfcm_send(m)',
WEB,
'import pywebpush as pw\npw.webpush()',
'from apns2.client import APNsClient\nself.client=APNsClient()\nself.client.send_notification()',
'from onesignal import OneSignalClient\nOneSignalClient().create_notification()',
'import firebase_admin as fa\nfa.messaging.Message()\nfa.messaging.send_multicast([])',
'import firebase_admin.messaging\nfirebase_admin.messaging.Message()\nfirebase_admin.messaging.send_all([])',
'import apns2.client as ac\napp.client=ac.APNsClient()\napp.client.send_notification()',
'import onesignal\nclient=onesignal.OneSignalClient()\nclient.create_notification()',
'import pywebpush\npywebpush.webpush()',
'from pywebpush import webpush as wp\nwp()',
'from aioapns import APNSClient as C\nc: object=C()\nc.send_notification()',
'from onesignal import Client\na=b=Client()\nb.create_notification()',
'from firebase_admin.messaging.sub import Message, send_all\nMessage()\nsend_all([])',
]
BAD = [
'import firebase_admin.messaging',
'from firebase_admin.messaging import Message\nMessage()',
'from firebase_admin.messaging import send\nsend(m)',
'def webpush(): pass\nwebpush()',
'client.send_notification()',
'from apns2.client import APNsClient\nclient=APNsClient()\nfn=client.send_notification\nfn()',
'from flask import Flask\napp=Flask(__name__)\n@app.post("/subscribe")\ndef subscribe():\n    subscriptions.append(request.json)',
'import smtplib\nsmtplib.SMTP("localhost").sendmail("a", "b", "hello")',
'from twilio.rest import Client\nClient().messages.create(body="hello", to="fixture")',
'channel="push"\ntoken="fixture"\nkey="marker"',
'from apns2 import APNsClient\nclient=APNsClient()\nother.send_notification()',
'from database import Client\nclient=Client()\nclient.send_notification()',
'class Client: pass\nclient=Client()\nclient.create_notification()',
'def push():\n    print("push")\npush()',
'client.register_device_token("fixture")',
'import boto3\nboto3.client("ses").send_email()',
'Message()\nsend()',
'"from pywebpush import webpush; webpush()"',
'# from pywebpush import webpush\n# webpush()',
]


def add_cases():
    for prefix, cases, good in [('good', GOOD, True), ('bad', BAD, False)]:
        for index, source in enumerate(cases, 1):
            def test(self, source=source, good=good):
                self.check_case(source, good)
            setattr(AuditTests, 'test_' + prefix + '_' + str(index).zfill(2), test)


add_cases()
