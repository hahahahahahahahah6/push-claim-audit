"""Read documentation and Python ASTs without executing project code."""
import ast
import fnmatch
import re
from pathlib import Path

PUSH = ('support for push notifications', 'support for push', 'push notification support', 'push notifications', 'push notification', 'push alerts', 'push alert', 'push messages', 'push message', 'sends push notifications', 'send push notifications', 'sends push', 'send push', 'push support', 'push enabled', 'push powered', 'push based', 'supports push notifications', 'supports push', 'uses push', 'using push', 'over push', 'via push', 'with push')
NOPUSH = ('no push notifications', 'no push notification', 'no push support', 'does not support push', 'does not send push', 'does not use push', 'push notifications not supported', 'push not supported', 'without push', 'no push')
CLIENTS = {'APNsClient', 'APNSClient', 'OneSignalClient', 'Client'}


def normalize(text):
    return re.sub(r'\s+', ' ', text.lower().replace("n't", ' not').replace('-', ' ')).strip()


def pattern(phrases):
    return re.compile(r'\b(?:' + '|'.join(re.escape(p) for p in sorted(phrases, key=len, reverse=True)) + r')\b')


def claims(text):
    lines, fence = [], None
    for line in text.splitlines():
        mark = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if mark:
            token = mark.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not line.strip()[len(token):].strip():
                fence = None
            lines.append('')
        elif fence is None:
            lines.append(line)
    positive = negative = False
    for paragraph in re.split(r'\n\s*\n', '\n'.join(lines)):
        text = normalize(paragraph)
        negative |= bool(pattern(NOPUSH).search(text))
        positive |= bool(pattern(PUSH).search(pattern(NOPUSH).sub(' ', text)))
    return positive, negative


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + '.' + node.attr if base else ''
    return ''


def push_module(name):
    return bool(set(name.split('.')) & {'apns', 'apns2', 'aioapns', 'onesignal'})


def evidence(text):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = node.module + '.' + item.name

    def resolve(node):
        name = dotted(node)
        first, sep, rest = name.partition('.')
        return aliases.get(first, '') + (sep + rest if sep else '') if first in aliases else ''

    def provider_call(node, provider, names):
        if not isinstance(node, ast.Call):
            return False
        path = resolve(node.func)
        module, _, symbol = path.rpartition('.')
        return symbol in names and (module == provider or module.startswith(provider + '.'))

    def creation(node):
        if not isinstance(node, ast.Call):
            return False
        module, _, symbol = resolve(node.func).rpartition('.')
        return symbol in CLIENTS and push_module(module)

    nodes = list(ast.walk(tree))
    bindings = set()
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and creation(node.value):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            bindings.update(dotted(t) for t in targets if dotted(t))
    message = send = usage = False
    for node in nodes:
        message |= provider_call(node, 'firebase_admin.messaging', {'Message'})
        send |= provider_call(node, 'firebase_admin.messaging', {'send', 'send_multicast', 'send_all'})
        if provider_call(node, 'pywebpush', {'webpush'}):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {'send_notification', 'create_notification'}:
            usage |= dotted(node.func.value) in bindings or creation(node.func.value)
    return bool((message and send) or usage)


def audit(root, ignores=(), fail_on='HIGH'):
    root = Path(root)
    if not root.is_dir() or root.stat().st_mode & 0o444 == 0:
        raise ValueError('root must be a readable directory')
    positive = negative = prod = test = False
    sources, claim_files = [], []
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root)
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root) or not path.is_file():
            continue
        if any(fnmatch.fnmatch(rel.as_posix(), glob) for glob in ignores):
            continue
        parts = rel.parts
        if (rel.as_posix() == 'README.md' or 'docs' in parts) and path.suffix.lower() == '.md':
            p, n = claims(path.read_text(encoding='utf-8'))
            if not ('tests' in parts or 'fixtures' in parts):
                positive |= p
            negative |= n
            if p or n:
                claim_files.append(rel.as_posix())
        if path.suffix != '.py' or any(p in {'fixtures', 'docs', 'examples'} for p in parts):
            continue
        is_test = 'tests' in parts or path.name.startswith('test_') or path.name.endswith('_test.py')
        if evidence(path.read_text(encoding='utf-8')):
            sources.append(rel.as_posix())
            if is_test:
                test = True
            else:
                prod = True
    findings = []
    if positive and not prod:
        findings.append(dict(rule='documented-push-claim-false', severity='MEDIUM' if test else 'HIGH', message='Documented device delivery lacks production send evidence.'))
    if negative and prod:
        findings.append(dict(rule='documented-no-push-claim-false', severity='HIGH', message='Documented absence conflicts with production send evidence.'))
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return dict(verdict='FAIL' if failed else 'PASS', findings=findings, claims=claim_files, evidence=sources)
