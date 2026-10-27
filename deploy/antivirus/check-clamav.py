#!/usr/bin/env python3
"""Read-only Linux FreshClam prerequisites; does not certify engine protection."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess


def check(config, freshclam):
    issues = []

    def fail(code, message):
        issues.append({'code': code, 'message': message})

    def read(path):
        values = {}
        try:
            for line in path.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                pair = line.split(None, 1)
                values.setdefault(pair[0], []).append(pair[1].strip() if len(pair) == 2 else '')
        except (OSError, UnicodeError):
            fail('config_unreadable', '配置不存在、不可读取或不是 UTF-8：' + str(path))
        return values

    def one(values, name, default=''):
        entries = values.get(name, [])
        if len(entries) > 1:
            fail('config_duplicate', '配置项不能重复：' + name)
            return ''
        return entries[0] if entries else default

    values = read(config)
    database = one(values, 'DatabaseDirectory')
    owner = one(values, 'DatabaseOwner', 'clamav')
    notify = one(values, 'NotifyClamd')
    if values.get('Example') is not None:
        fail('example_enabled', '必须移除示例配置中的 Example。')
    if values.get('DatabaseMirror') != ['database.clamav.net'] or values.get('PrivateMirror'):
        fail('official_mirror_required', '此部署配置使用官方 database.clamav.net；私有镜像需另行验证。')
    if one(values, 'Checks') != '24':
        fail('hourly_checks_required', '此部署配置须使用 Checks 24。')
    for name in ('ScriptedUpdates', 'TestDatabases'):
        if one(values, name).lower() != 'yes':
            fail('validation_required', name + ' 须为 yes，不能关闭校验以绕过容量限制。')
    if values.get('DatabaseCustomURL') or values.get('DatabaseOptional'):
        fail('additional_source_unverified', '额外数据库来源不在此官方库部署检查范围。')

    database_path = Path(database) if database else None
    if database_path is None or not database_path.is_absolute():
        fail('database_path_required', 'DatabaseDirectory 须为绝对路径。')
        database_path = None
    account = None
    try:
        account = pwd.getpwnam(owner)
        if account.pw_uid == 0:
            fail('unprivileged_owner_required', 'FreshClam 应使用专用非 root 账号。')
    except KeyError:
        fail('database_owner_missing', 'DatabaseOwner 对应的系统账号不存在。')
    try:
        if database_path is not None:
            info = database_path.stat()
            if not stat.S_ISDIR(info.st_mode):
                raise NotADirectoryError()
            if account and (info.st_uid != account.pw_uid or info.st_mode & 0o700 != 0o700):
                fail('database_permissions', '数据库目录须由 DatabaseOwner 持有，且属主可读写进入。')
            if info.st_mode & 0o002:
                fail('database_world_writable', '数据库目录不可允许其他用户写入。')
    except OSError:
        fail('database_directory_missing', '须先创建数据库目录并设置服务账号权限。')

    if not notify or not Path(notify).is_absolute():
        fail('notify_config_required', 'NotifyClamd 须指向实际 clamd 配置的绝对路径。')
    else:
        clamd_values = read(Path(notify))
        clamd_database = one(clamd_values, 'DatabaseDirectory')
        if not clamd_database or not Path(clamd_database).is_absolute():
            fail('clamd_database_required', 'clamd 须显式配置数据库目录绝对路径。')
        elif database_path and Path(clamd_database).resolve() != database_path.resolve():
            fail('database_mismatch', 'FreshClam 与 clamd 的 DatabaseDirectory 不一致。')

    binary = shutil.which(freshclam)
    version = None
    if binary is None:
        fail('freshclam_missing', '须先安装受支持的 FreshClam 及其运行库。')
    else:
        try:
            # --version parses the config but does not contact the update CDN.
            probe = subprocess.run([binary, '--config-file=' + str(config), '--version'],
                                   capture_output=True, text=True, timeout=10)
            identity = re.fullmatch(r'ClamAV ([0-9]+\.[0-9]+\.[0-9]+)(?:/[^\r\n]*)?\s*', probe.stdout)
            if probe.returncode != 0 or identity is None:
                fail('native_config_rejected', '真实 FreshClam 未能加载程序或解析配置；请本机检查其错误输出。')
            else:
                version = identity[1]
                if tuple(map(int, version.split('.'))) >= (1, 5, 0):
                    certs = Path(one(values, 'CVDCertsDirectory', '/etc/clamav/certs'))
                    engine_certs = Path(os.environ.get('CVD_CERTS_DIR') or '/etc/clamav/certs')
                    if certs.resolve() != engine_certs.resolve():
                        fail('cvd_certificates_path_mismatch',
                             '自定义 CVDCertsDirectory 时，须让 CVD_CERTS_DIR 与它一致，供库加载校验使用。')
                    for path in {certs, engine_certs}:
                        if not path.is_dir() or not any(path.glob('*.crt')):
                            fail('cvd_certificates_missing', 'ClamAV 1.5 的官方数据库验签证书缺失；须保留软件包自带证书。')
                            break
        except (OSError, subprocess.TimeoutExpired):
            fail('native_probe_failed', '真实 FreshClam 程序检查失败或超过 10 秒。')

    updater_pids = []
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if (process / 'comm').read_text().strip() == 'freshclam':
                updater_pids.append(int(process.name))
        except OSError:
            continue
    if updater_pids:
        fail('updater_already_running', '已有 FreshClam 进程；先确认所属服务及数据库，避免并行维护。')

    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    available_mib = int(mem['MemAvailable'].split()[0]) // 1024
    # Reserve enough for full database load testing; this is not a build limit.
    minimum_available_mib = 3072
    if available_mib < minimum_available_mib:
        fail('insufficient_memory', '完整官方库初始化／加载校验至少预留 3072 MiB 可用内存；请使用容量合适的目标机。')
    disk_path = database_path if database_path is not None else config.parent
    while not disk_path.exists():
        disk_path = disk_path.parent
    disk_free_mib = shutil.disk_usage(disk_path).free // (1 << 20)
    # Keep a 2 GiB reserve plus 1 GiB for databases/download/reload intermediates.
    if disk_free_mib < 3072:
        fail('insufficient_disk', '数据库所在文件系统至少预留 3072 MiB；保留 2 GiB 余量和初始化空间。')
    return {'scope': 'freshclam_initialization_prerequisites', 'ready': not issues,
            'config': str(config), 'freshclamVersion': version,
            'availableMiB': available_mib, 'databaseDiskFreeMiB': disk_free_mib,
            'existingUpdaterPids': sorted(updater_pids), 'issues': issues,
            'onlineUpdateAccepted': False, 'clamdAndAgentProtectionAccepted': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/etc/alinksec/freshclam.conf'))
    parser.add_argument('--freshclam', default='/usr/bin/freshclam')
    args = parser.parse_args()
    result = check(args.config.resolve(), args.freshclam)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
