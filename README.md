# ssh-copy-id

A Python implementation of the OpenSSH `ssh-copy-id` workflow for installing an SSH public key on a remote host.

## Features

- Copies a public key to a remote server
- Supports force mode and dry-run mode
- Supports SSH config lookups and an alternative config file
- Accepts either `user host` or `user@host`
- Includes debug output for troubleshooting

## Requirements

- Python 3.12+
- `paramiko`
- A local SSH key pair

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

```bash
python ssh-copy-id.py -h
python ssh-copy-id.py -f -n -i ~/.ssh/id_rsa.pub USER HOST
python ssh-copy-id.py -F ~/.ssh/config USER@HOST
```

## Options

- `-h`, `--help` : show help
- `-f` : force mode
- `-n` : dry run
- `-x` : debug output
- `-i` : identity file
- `-p` : port
- `-F` : alternative SSH config file
- `-t` : target path

## Notes

This project mirrors the standard OpenSSH `ssh-copy-id` approach, but is implemented in Python for portability and easier scripting.
