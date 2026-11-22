"""Real REST revocation matrix shared by standalone restart and cluster runners."""
import hashlib
import json
import secrets
import urllib.error
import urllib.request


def verify(ports, administrator, password, restart):
    observations = []
    phase = ['setup']

    def request(port, path, token=None, body=None, method=None, expected=200):
        req = urllib.request.Request(f'http://127.0.0.1:{port}' + path,
                data=None if body is None else json.dumps(body).encode(), method=method,
                headers={'Content-Type': 'application/json', **({'Authorization': 'Bearer ' + token} if token else {})})
        try:
            response = urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
            assert response.status == expected, (path, response.status, expected)
            if expected == 200:
                assert result['code'] == 0, (path, result['code'])
            observations.append({'stage': phase[0], 'port': port, 'path': path, 'method': req.get_method(), 'status': response.status,
                                 'tokenSHA256': hashlib.sha256(token.encode()).hexdigest() if token else None})
            return result.get('data')

    def login(name, value):
        return request(ports[0], '/api/auth/login', body={'username': name, 'password': value})['token']

    rule = request(ports[0], '/api/protect/rules', administrator)[0]
    rule_path = '/api/protect/rules/' + rule['rule_id']
    body = {'enabled': bool(rule['enabled'])}
    prefix = 'rev004_' + secrets.token_hex(4)
    saved = {}
    for case in ['logout', 'disabled', 'demoted', 'password']:
        phase[0] = 'setup_' + case
        name = prefix + '_' + case
        request(ports[0], '/api/users', administrator,
                {'username': name, 'realName': 'isolated revocation fixture', 'password': password, 'role': 'admin'})
        token = login(name, password)
        saved[case] = token
        for port in ports:
            request(port, rule_path, token, body, 'PUT')
        if case == 'logout':
            request(ports[-1], '/api/auth/logout', token, {})
        elif case == 'password':
            saved['password_second_session'] = login(name, password)
            changed_password = secrets.token_urlsafe(24)
            request(ports[-1], '/api/auth/password', token, {'oldPassword': password, 'password': changed_password})
        else:
            user = next(row for row in request(ports[0], '/api/users', administrator)['list'] if row['username'] == name)
            request(ports[-1], '/api/users/' + str(user['id']), administrator,
                    {'role': 'viewer' if case == 'demoted' else 'admin', 'status': '1' if case == 'demoted' else '0',
                     'version': str(user['auth_version'])}, 'PUT')

    def revoked(stage):
        phase[0] = stage
        before = request(ports[0], '/api/protect/rules', administrator)
        for port in ports:
            # A surviving valid session proves this is revocation, not signing-key rotation.
            request(port, '/api/users', administrator)
            for token in saved.values():
                request(port, '/api/protect/rules', token, expected=401)
                request(port, rule_path, token, body, 'PUT', expected=401)
        assert request(ports[0], '/api/protect/rules', administrator) == before
        return {'stage': stage, 'revokedSessions': len(saved), 'replicas': len(ports), 'unchangedRules': True}

    stages = [revoked('before_restart')]
    process = restart()
    assert process['beforePid'] != process['afterPid'] and process['signingKeyUnchanged']
    stages.append(revoked('after_actual_jvm_restart'))
    phase[0] = 'fresh_sessions'
    viewer = login(prefix + '_demoted', password)
    for port in ports:
        request(port, '/api/protect/rules', viewer)
        request(port, rule_path, viewer, body, 'PUT', expected=403)
    fresh = login(prefix + '_password', changed_password)
    for port in ports:
        request(port, rule_path, fresh, body, 'PUT')
    return {'accepted': True, 'scope': 'actual_rest_and_jvm_restart', 'replicas': len(ports), 'stages': stages,
            'restart': process, 'freshViewerWriteDenied': True, 'freshPasswordSessionAccepted': True,
            'cases': {case: hashlib.sha256(token.encode()).hexdigest() for case, token in saved.items()}, 'observations': observations}
