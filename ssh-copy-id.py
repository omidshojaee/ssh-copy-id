import argparse
import getpass
import os
import sys

import paramiko


def copy_ssh_id(hostname, username, password, port, key_path=None):
    """
    Copy the SSH public key to the specified remote server.

    :param hostname: Remote server IP or FQDN
    :param username: SSH username
    :param password: SSH password
    :param port: SSH port
    :param key_path: Path to the public key file (optional)
    :return: True if successful, False otherwise
    """
    # If no key path is provided, use the default location
    if not key_path:
        key_path = os.path.expanduser('~/.ssh/id_rsa.pub')

    # Check if the public key file exists
    if not os.path.isfile(key_path):
        print(f"Public key file not found: {key_path}")
        return False

    try:
        # Read the content of the public key file
        with open(key_path, 'r') as key_file:
            key_content = key_file.read().strip()

        # Initialize SSH client and connect to the remote server
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, port=port, username=username, password=password)

        # Ensure .ssh directory exists with correct permissions
        ssh.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')

        # Check if authorized_keys file already exists
        stdin, stdout, stderr = ssh.exec_command(
            'test -f ~/.ssh/authorized_keys && echo "EXISTS" || echo "NOT_EXISTS"'
        )
        result = stdout.read().decode().strip()

        if result == "EXISTS":
            # Check if the key is already in authorized_keys
            check_cmd = f'grep -qF "{key_content}" ~/.ssh/authorized_keys'
            stdin, stdout, stderr = ssh.exec_command(check_cmd)
            if stdout.channel.recv_exit_status() == 0:
                print(
                    f"The key already exists in ~/.ssh/authorized_keys for {username}@{hostname}"
                )
                return True
            else:
                # Append the new key if it doesn't exist
                command = f'echo "{key_content}" >> ~/.ssh/authorized_keys'
        else:
            # Create new authorized_keys file with the key
            command = f'echo "{key_content}" > ~/.ssh/authorized_keys'

        # Execute the command to add the key
        stdin, stdout, stderr = ssh.exec_command(command)

        # Ensure correct permissions for authorized_keys file
        ssh.exec_command('chmod 600 ~/.ssh/authorized_keys')

        # Verify the key was added successfully
        verify_cmd = f'grep -qF "{key_content}" ~/.ssh/authorized_keys'
        stdin, stdout, stderr = ssh.exec_command(verify_cmd)
        if stdout.channel.recv_exit_status() != 0:
            print(
                f"Failed to add the key to ~/.ssh/authorized_keys for {username}@{hostname}"
            )
            return False

        print(f"Public key successfully copied to {username}@{hostname}")
        return True

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return False

    finally:
        # Always close the SSH connection
        ssh.close()


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Copy SSH public key to a remote server", add_help=False
    )

    # Define arguments
    parser.add_argument("hostname", help="Remote server IP or FQDN", nargs="?")
    parser.add_argument("username", help="SSH username", nargs="?")
    parser.add_argument("password", help="SSH password", nargs="?")
    parser.add_argument("port", type=int, help="SSH port", nargs="?")
    parser.add_argument("--key", help="Path to the public key file (optional)")
    parser.add_argument(
        "--h", "--help", action="help", help="Show this help message and exit"
    )

    # Parse arguments
    args = parser.parse_args()

    # Check if all required arguments are provided
    if not all([args.hostname, args.username, args.password, args.port]):
        parser.print_help()
        sys.exit(1)

    # Call the copy_ssh_id function with provided arguments
    success = copy_ssh_id(
        args.hostname, args.username, args.password, args.port, args.key
    )

    # Exit with appropriate status code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
