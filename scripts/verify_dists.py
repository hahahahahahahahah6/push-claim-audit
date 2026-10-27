"""Verify distribution installs away from the source checkout."""
import json
from pathlib import Path
import subprocess
import tempfile
import venv

ROOT = Path(__file__).resolve().parents[1]


def run(command, cwd, expected=0):
    result = subprocess.run([str(p) for p in command], cwd=cwd, text=True, capture_output=True)
    if result.returncode != expected:
        raise AssertionError((command, result.returncode, result.stdout, result.stderr))
    return result.stdout.strip()


def main():
    for artifact in sorted((ROOT / 'dist').iterdir()):
        with tempfile.TemporaryDirectory(prefix='push-claim-install-') as directory:
            work = Path(directory)
            env = work / 'venv'
            venv.EnvBuilder(with_pip=True).create(env)
            interpreter = env / 'bin/python3'
            run([interpreter, '-m', 'pip', 'install', artifact], work)
            for command in ([env / 'bin/push-claim-audit'], [interpreter, '-m', 'push_claim_audit']):
                assert run(command + ['--version'], work) == '0.1.0'
                good = json.loads(run(command + [ROOT / 'tests/fixtures/good', '--json'], work))
                assert good['verdict'] == 'PASS' and good['findings'] == []
                bad = json.loads(run(command + [ROOT / 'tests/fixtures/bad', '--json'], work, 2))
                assert bad['verdict'] == 'FAIL'
                assert [(f['rule'], f['severity']) for f in bad['findings']] == [('documented-push-claim-false', 'HIGH')]
                own = json.loads(run(command + [ROOT, '--json'], work))
                assert own['verdict'] == 'PASS' and own['claims'] == [] and own['findings'] == []
            print(artifact.name + ': fresh install PASS; both entry points, good=0, bad=2 exact HIGH rule, version=0.1.0, self-audit=0 no claim')


if __name__ == '__main__':
    main()
