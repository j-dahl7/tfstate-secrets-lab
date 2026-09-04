#!/usr/bin/env python3
"""Exercise the repository config with the actual pinned Trivy CLI; no apply/state."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures' / 'trivy-raw'
EXPECTED_ID = 'NLSCFG001'


def run(trivy, *args):
    result = subprocess.run([trivy, *map(str, args)], cwd=ROOT, text=True,
                            encoding='utf-8', capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f'Trivy failed ({result.returncode}): {result.stderr}')
    return json.loads(result.stdout)


def findings(trivy, config, fixture):
    with tempfile.TemporaryDirectory(prefix='nls-trivy-cache-') as cache:
        result = run(trivy, 'config', '--config', config, '--skip-check-update',
                     '--skip-version-check', '--cache-dir', cache,
                     '--config-check', FIXTURES / 'policy.rego', '--namespaces', 'user',
                     '--format', 'json', '--exit-code', '0', FIXTURES / fixture)
    return [item for group in result.get('Results', [])
            for item in group.get('Misconfigurations', []) if item.get('ID') == EXPECTED_ID]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trivy', default='trivy')
    args = parser.parse_args()
    version = run(args.trivy, '--version', '--format', 'json')['Version']
    if version != '0.70.0':
        raise RuntimeError(f'Expected pinned Trivy 0.70.0, got {version}')
    if len(findings(args.trivy, ROOT / 'trivy.yaml', 'bad')) != 1:
        raise RuntimeError('Repository config failed to activate the terraform-raw fixture check')
    if findings(args.trivy, ROOT / 'trivy.yaml', 'good'):
        raise RuntimeError('Write-only negative control unexpectedly matched')
    with tempfile.TemporaryDirectory(prefix='nls-trivy-config-') as directory:
        broken = Path(directory) / 'broken.yaml'
        broken.write_text('misconfiguration:\n  scanners: [terraform]\n'
                          '  terraform:\n    raw-config-scanners: [terraform]\n', encoding='utf-8')
        if findings(args.trivy, broken, 'bad'):
            raise RuntimeError('Negative config control unexpectedly enabled raw scanning')
    print('PASS: Trivy 0.70.0 config activates raw policy; good and broken-config controls do not match')


if __name__ == '__main__':
    main()
