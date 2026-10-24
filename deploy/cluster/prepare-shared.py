#!/usr/bin/env python3
"""Prepare the explicit cluster marker after the single bootstrap process has stopped."""
import argparse
import json
import os
from pathlib import Path
import stat
import uuid

def prepare(directory, deployment):
    if str(uuid.UUID(deployment)) != deployment:
        raise ValueError('Use a lowercase deployment UUID')
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Shared directory is missing')
    marker = root / '.cluster-deployment-id'
    if marker.exists() or marker.is_symlink():
        raise ValueError('Deployment marker already exists; it is never overwritten')
    for relative in ['certs/ca.crt', 'certs/ca.key', 'certs/server.crt', 'certs/server.key', 'web-tls/server.crt', 'web-tls/server.key']:
        file = root / relative
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 131072 or not file.resolve().is_relative_to(root):
            raise ValueError('Preinitialized shared PKI is missing or outside the shared directory')
    for name in ['server.crt', 'server.key']:
        if (root / 'certs' / name).read_bytes() != (root / 'web-tls' / name).read_bytes():
            raise ValueError('Web TLS material differs from server material')
    jwt_file = root / 'jwt.secret'
    if jwt_file.is_symlink() or jwt_file.exists() and (not jwt_file.is_file() or not jwt_file.resolve().is_relative_to(root)):
        raise ValueError('JWT file leaves the shared directory')
    secret = os.environ.get('ALINKSEC_JWT_SECRET', '')
    if not secret:
        file = root / 'jwt.secret'
        if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(root) or file.stat().st_size > 4096:
            raise ValueError('Preinitialized shared JWT secret is missing')
        secret = file.read_text().strip()
    if not 32 <= len(secret) <= 4096:
        raise ValueError('JWT secret must contain 32 to 4096 characters')
    directories = [root / name for name in ['certs', 'web-tls', 'libraries', 'signature', 'patch', 'upgrade', '.cluster-probes']]
    for target in directories:
        if not target.resolve().is_relative_to(root) or target.exists() and not target.is_dir():
            raise ValueError('Storage path leaves the shared directory or is not a directory')
    for relative in ['certs/ca.key', 'certs/server.key', 'web-tls/server.key', 'jwt.secret']:
        file = root / relative
        if file.exists():
            file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    for target in directories:
        target.mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        output.write(deployment + '\n')
        output.flush()
        os.fsync(output.fileno())
    return {'deploymentId': deployment, 'sharedDirectory': str(root), 'prepared': True}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('shared_directory')
    parser.add_argument('deployment_id')
    args = parser.parse_args()
    print(json.dumps(prepare(args.shared_directory, args.deployment_id)))
