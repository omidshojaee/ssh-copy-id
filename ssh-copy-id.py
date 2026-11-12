"""
ssh-copy-id installs an SSH key on a server as an authorized key.
Its purpose is to provide access without requiring a password for each login.
This facilitates automated, passwordless logins and single sign-on using the SSH protocol.

This is a Python re-implementation of the OpenSSH ssh-copy-id shell script,
built on top of paramiko since Windows has no bundled ssh-copy-id.
"""

import argparse
import getpass
import glob
import logging
import os
import posixpath
import shlex
import sys

import paramiko

PROG = os.path.basename(sys.argv[0]) or 'ssh-copy-id'


def parse_pubkey_line(line):
    """Split a public key line into (key_type, base64_blob, comment)."""
    parts = line.strip().split(None, 2)
    if len(parts) < 2:
        return None
    key_type, blob = parts[0], parts[1]
    comment = parts[2] if len(parts) > 2 else ''
    return key_type, blob, comment


def load_keys_from_file(path):
    keys = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parsed = parse_pubkey_line(line)
            if parsed:
                keys.append(parsed)
    return keys


def load_keys_from_agent(debug=False):
    """Mirror 'ssh-add -L': return public keys currently loaded in the SSH agent."""
    try:
        agent = paramiko.Agent()
        agent_keys = agent.get_keys()
        agent.close()
    except Exception as e:
        if debug:
            print(f"[DEBUG] Could not query ssh-agent: {e}")
        return []

    keys = []
    for key in agent_keys:
        comment = getattr(key, 'comment', '') or ''
        keys.append((key.get_name(), key.get_base64(), comment))
    return keys


def default_identity_file():
    """
    Mirror OpenSSH's default_ID_file: the most recently modified
    ~/.ssh/id*.pub file, excluding *-cert.pub files.
    """
    ssh_dir = os.path.expanduser('~/.ssh')
    candidates = [
        p for p in glob.glob(os.path.join(ssh_dir, 'id*.pub'))
        if not p.endswith('-cert.pub')
    ]
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def resolve_keys_to_install(identity_file, config_identity_file, debug=False):
    """
    Returns (keys, source_description) where keys is a list of
    (key_type, base64_blob, comment) tuples.

    Priority, matching ssh-copy-id:
      -i <file>          -> only the key(s) in <file>
      -i (no file given)  -> skip the agent, use the default/config identity file
      (no -i at all)      -> try the agent first, then fall back
    """
    if identity_file:
        path = os.path.expanduser(identity_file)
        if not path.endswith('.pub'):
            path += '.pub'
        if not os.path.exists(path):
            print(f"{PROG}: ERROR: identity file '{path}' does not exist.")
            sys.exit(1)
        keys = load_keys_from_file(path)
        if not keys:
            print(f"{PROG}: ERROR: '{path}' does not contain a valid public key.")
            sys.exit(1)
        return keys, path

    if identity_file is None:
        agent_keys = load_keys_from_agent(debug=debug)
        if agent_keys:
            return agent_keys, 'the authentication agent'

    fallback = config_identity_file or default_identity_file()
    if not fallback or not os.path.exists(fallback):
        print(f"{PROG}: ERROR: No identities found.")
        sys.exit(1)
    keys = load_keys_from_file(fallback)
    if not keys:
        print(f"{PROG}: ERROR: '{fallback}' does not contain a valid public key.")
        sys.exit(1)
    return keys, fallback


def apply_ssh_options(ssh, ssh_options, connect_kwargs, debug=False):
    """Best-effort mapping of '-o Option=value' onto paramiko connection behaviour."""
    for opt in ssh_options:
        if '=' in opt:
            key, value = opt.split('=', 1)
        else:
            key, value = opt, None
        key_lower = key.strip().lower()
        value = value.strip() if value is not None else None

        if key_lower == 'stricthostkeychecking':
            if value and value.lower() == 'yes':
                ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        elif key_lower == 'userknownhostsfile' and value:
            known_hosts = os.path.expanduser(value)
            if os.path.exists(known_hosts):
                ssh.load_host_keys(known_hosts)
        elif key_lower == 'connecttimeout' and value:
            connect_kwargs['timeout'] = float(value)
        elif key_lower == 'port' and value:
            connect_kwargs.setdefault('_port_override', int(value))
        elif key_lower == 'identitiesonly' and value and value.lower() == 'yes':
            connect_kwargs['allow_agent'] = False
            connect_kwargs['look_for_keys'] = False
        elif debug:
            print(f"[DEBUG] Ignoring unsupported -o option: {opt}")


def check_remote_for_duplicates(ssh, target_path, keys):
    """Return the subset of keys not already present on the remote authorized_keys file."""
    stdin, stdout, stderr = ssh.exec_command(f'cat -- {shlex.quote(target_path)} 2>/dev/null')
    remote_content = stdout.read().decode('utf-8', errors='replace')
    remaining = [k for k in keys if k[1] not in remote_content]
    return remaining


def install_keys_exec(ssh, target_path, keys):
    key_lines = []
    for key_type, blob, comment in keys:
        line = f'{key_type} {blob}'
        if comment:
            line += f' {comment}'
        key_lines.append(line)
    payload = '\n'.join(key_lines) + '\n'

    parent_dir = posixpath.dirname(target_path) or '.'
    cmd = (
        f'umask 077; mkdir -p -- {shlex.quote(parent_dir)} 2>/dev/null; '
        f'cat >> {shlex.quote(target_path)} && chmod 600 -- {shlex.quote(target_path)}'
    )
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdin.write(payload)
    stdin.flush()
    stdin.channel.shutdown_write()
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        err = stderr.read().decode('utf-8', errors='replace')
        raise RuntimeError(err.strip() or f'remote command exited with status {exit_status}')


def install_keys_sftp(ssh, target_path, keys):
    """Mirror ssh-copy-id's -s mode: edit authorized_keys locally via sftp."""
    sftp = ssh.open_sftp()
    try:
        home = sftp.normalize('.')
        remote_path = target_path
        if remote_path.startswith('~/'):
            remote_path = posixpath.join(home, remote_path[2:])
        elif not remote_path.startswith('/'):
            remote_path = posixpath.join(home, remote_path)

        ssh_dir = posixpath.dirname(remote_path)
        try:
            sftp.stat(ssh_dir)
        except FileNotFoundError:
            sftp.mkdir(ssh_dir, mode=0o700)

        try:
            with sftp.open(remote_path, 'r') as f:
                existing = f.read().decode('utf-8', errors='replace')
        except FileNotFoundError:
            existing = ''

        key_lines = []
        for key_type, blob, comment in keys:
            line = f'{key_type} {blob}'
            if comment:
                line += f' {comment}'
            key_lines.append(line)

        new_content = existing
        if new_content and not new_content.endswith('\n'):
            new_content += '\n'
        new_content += '\n'.join(key_lines) + '\n'

        with sftp.open(remote_path, 'w') as f:
            f.write(new_content)
        sftp.chmod(remote_path, 0o600)
    finally:
        sftp.close()


def ssh_copy_id(
    user,
    host,
    port=22,
    identity_file=None,
    target_path='.ssh/authorized_keys',
    force=False,
    dry_run=False,
    debug=False,
    config_file=None,
    sftp_mode=False,
    ssh_options=None,
):
    ssh_options = ssh_options or []

    if debug:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(message)s')
        logging.getLogger('paramiko').setLevel(logging.DEBUG)
        print(f"[DEBUG] user={user} host={host} port={port}")
        print(f"[DEBUG] identity_file={identity_file!r}")
        print(f"[DEBUG] target_path={target_path} force={force} dry_run={dry_run} sftp_mode={sftp_mode}")

    ssh_config_path = (
        os.path.expanduser('~/.ssh/config')
        if config_file is None
        else os.path.expanduser(config_file)
    )
    config_identity_file = None

    if os.path.exists(ssh_config_path):
        ssh_config = paramiko.config.SSHConfig()
        with open(ssh_config_path, 'r') as f:
            ssh_config.parse(f)
        lookup = ssh_config.lookup(host)
        host = lookup.get('hostname', host)
        port = int(lookup.get('port', port))
        user = lookup.get('user', user)
        if debug:
            print(f"[DEBUG] Loaded SSH config from {ssh_config_path}: {lookup}")
        if lookup.get('identityfile'):
            config_identity_file = os.path.expanduser(lookup['identityfile'][0])
    elif debug:
        print(f"[DEBUG] No SSH config found at {ssh_config_path}")

    keys, source = resolve_keys_to_install(identity_file, config_identity_file, debug=debug)
    print(f'{PROG}: INFO: Source of key(s) to be installed: "{source}"')

    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = {}
    apply_ssh_options(ssh, ssh_options, connect_kwargs, debug=debug)
    port = connect_kwargs.pop('_port_override', port)

    explicit_key_filename = identity_file if identity_file else None
    if explicit_key_filename:
        explicit_key_filename = os.path.expanduser(explicit_key_filename)
        if not explicit_key_filename.endswith('.pub'):
            explicit_key_filename += '.pub'
        explicit_key_filename = explicit_key_filename[:-4]  # private key path, strip .pub

    try:
        if debug:
            print(f"[DEBUG] Connecting to {user}@{host}:{port}")

        try:
            ssh.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=explicit_key_filename,
                look_for_keys=connect_kwargs.pop('look_for_keys', True),
                allow_agent=connect_kwargs.pop('allow_agent', True),
                **connect_kwargs,
            )
        except paramiko.AuthenticationException:
            if debug:
                print('[DEBUG] SSH key authentication failed; prompting for password')
            password = getpass.getpass(f"Password for {user}@{host}: ")
            ssh.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                key_filename=explicit_key_filename,
                look_for_keys=True,
                allow_agent=True,
            )
    except Exception as e:
        print(f"{PROG}: ERROR: Could not connect to {user}@{host}:{port}. {e}")
        if debug:
            logging.exception("SSH connection failed")
        sys.exit(1)

    try:
        if force:
            remaining = keys
        else:
            print(
                f'{PROG}: INFO: attempting to filter out any key(s) that are already installed'
            )
            remaining = check_remote_for_duplicates(ssh, target_path, keys)

        if not remaining:
            print(f'{PROG}: WARNING: All keys were already installed')
            return

        if dry_run:
            print(
                f'{PROG}: INFO: Dry run -- the following key(s) would be installed '
                f'on {user}@{host}:{target_path}:'
            )
            for key_type, blob, comment in remaining:
                line = f'{key_type} {blob}'
                if comment:
                    line += f' {comment}'
                print(line)
            return

        print(
            f'{PROG}: INFO: {len(remaining)} key(s) remain to be installed -- '
            f'if you are prompted now it is to install the new keys'
        )

        try:
            if sftp_mode:
                install_keys_sftp(ssh, target_path, remaining)
            else:
                install_keys_exec(ssh, target_path, remaining)
        except Exception as e:
            print(f"{PROG}: ERROR: Failed to install key(s): {e}")
            sys.exit(1)

        print(f'\nNumber of key(s) added: {len(remaining)}\n')
        print(f'Now try logging into the machine, with:   "ssh \'{user}@{host}\'"')
        print('and check to make sure that only the key(s) you wanted were added.')
    finally:
        ssh.close()


def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(
        prog=PROG,
        description='Install an SSH key on a server as an authorized key.',
        add_help=False,
    )

    # Define arguments
    parser.add_argument('-h', '--help', action='help', help='print this help')
    parser.add_argument(
        '-f',
        action='store_true',
        help='force mode \t-- copy keys without trying to check if they are already installed',
        dest='force',
    )
    parser.add_argument(
        '-n',
        action='store_true',
        help='dry run \t-- print the key(s) that would be installed without installing them',
        dest='dry_run',
    )
    parser.add_argument(
        '-s',
        action='store_true',
        help='sftp mode \t-- install the key by downloading, editing, and re-uploading authorized_keys',
        dest='sftp_mode',
    )
    parser.add_argument(
        '-x',
        action='store_true',
        help='debug \t-- enables -x in the shell, for debugging',
        dest='debug',
    )
    parser.add_argument(
        '-i',
        metavar='',
        nargs='?',
        const='',
        default=None,
        dest='identity_file',
        help=(
            'identity file \t-- use only the key(s) in identity_file instead of the '
            'default list from the agent or the default identity file'
        ),
    )
    parser.add_argument(
        '-p',
        metavar='',
        type=int,
        default=22,
        dest='port',
        help='port \t-- specifies the port to connect to on the remote host (default is 22)',
    )
    parser.add_argument(
        '-F',
        metavar='',
        default=None,
        dest='config_file',
        help='alternative config file \t-- read the connection settings from an alternative SSH config file (default is ~/.ssh/config)',
    )
    parser.add_argument(
        '-o',
        metavar='',
        action='append',
        default=[],
        dest='ssh_options',
        help='ssh option \t-- an ssh -o style option, passed through where supported (repeatable)',
    )
    parser.add_argument(
        '-t',
        metavar='',
        default='.ssh/authorized_keys',
        dest='target_path',
        help='target path \t-- the path on the target system where the keys should be added (default is .ssh/authorized_keys)',
    )
    parser.add_argument('user', nargs='?', default=None)
    parser.add_argument('host', nargs='?', default=None)

    # Parse arguments
    args = parser.parse_args()

    if args.host is None and args.user and '@' in args.user:
        args.user, args.host = args.user.split('@', 1)

    # Check if required arguments are provided
    if not args.user or not args.host:
        parser.print_help()
        sys.exit(1)

    ssh_copy_id(
        user=args.user,
        host=args.host,
        port=args.port,
        identity_file=args.identity_file,
        target_path=args.target_path,
        force=args.force,
        dry_run=args.dry_run,
        debug=args.debug,
        config_file=args.config_file,
        sftp_mode=args.sftp_mode,
        ssh_options=args.ssh_options,
    )


if __name__ == '__main__':
    main()
