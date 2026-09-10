"""
ssh-copy-id installs an SSH key on a server as an authorized key.
Its purpose is to provide access without requiring a password for each login.
This facilitates automated, passwordless logins and single sign-on using the SSH protocol.
"""

import argparse
import getpass
import logging
import os
import sys

import paramiko


def ssh_copy_id(
    user,
    host,
    port=22,
    identity_file=None,
    target_path='~/.ssh/authorized_keys',
    force=False,
    dry_run=False,
    debug=False,
    config_file=None,
):
    if debug:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(message)s')
        logging.getLogger('paramiko').setLevel(logging.DEBUG)
        print(f"[DEBUG] user={user} host={host} port={port}")
        print(f"[DEBUG] identity_file={identity_file}")
        print(f"[DEBUG] target_path={target_path} force={force} dry_run={dry_run}")

    ssh_config_path = (
        os.path.expanduser('~/.ssh/config')
        if config_file is None
        else os.path.expanduser(config_file)
    )
    lookup = {'hostname': host, 'port': str(port), 'user': user}

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
        if identity_file is None and lookup.get('identityfile'):
            identity_file = lookup['identityfile'][0]
    elif debug:
        print(f"[DEBUG] No SSH config found at {ssh_config_path}")

    # Load the SSH key
    if identity_file is None:
        identity_file = os.path.expanduser('~/.ssh/id_rsa.pub')
    else:
        identity_file = os.path.expanduser(identity_file)

    if not os.path.exists(identity_file):
        print(f"Error: Identity file '{identity_file}' does not exist.")
        sys.exit(1)

    if debug:
        print(f"[DEBUG] Loading public key from {identity_file}")

    with open(identity_file, 'r') as f:
        public_key = f.read().strip()

    # Establish SSH connection
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if debug:
            print(f"[DEBUG] Connecting to {user}@{host}:{port}")

        try:
            ssh.connect(
                hostname=host,
                port=port,
                username=user,
                key_filename=identity_file,
                look_for_keys=True,
                allow_agent=True,
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
                key_filename=identity_file,
                look_for_keys=True,
                allow_agent=True,
            )
    except Exception as e:
        print(f"Error: Could not connect to {user}@{host}:{port}. {e}")
        if debug:
            logging.exception("SSH connection failed")
        sys.exit(1)

    # Check if the key is already installed
    if not force:
        stdin, stdout, stderr = ssh.exec_command(f'grep "{public_key}" {target_path}')
        if stdout.read():
            print("The key is already installed on the server.")
            ssh.close()
            return

    # Install the key
    if dry_run:
        print(
            f"Dry run: The following key would be copied to {user}@{host}:{target_path}:\n{public_key}"
        )
    else:
        ssh.exec_command(
            f'mkdir -p ~/.ssh && echo "{public_key}" >> {target_path} && chmod 600 {target_path}'
        )
        print(f"Successfully installed the key on {user}@{host}:{target_path}")

    ssh.close()


def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(
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
        help='dry run \t-- print the key that would be copied without installing it',
        dest='dry_run',
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
        default=None,
        dest='identity_file',
        help='identity file \t-- specifies the identity file that is to be copied (default is ~/.ssh/id_rsa.pub)',
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
        '-t',
        metavar='',
        default='~/.ssh/authorized_keys',
        dest='target_path',
        help='target path \t-- the path on the target system where the keys should be added (default is ~/.ssh/authorized_keys)',
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
    )


if __name__ == '__main__':
    main()
