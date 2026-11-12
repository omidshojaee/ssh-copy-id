# ssh-copy-id

A Python implementation of the OpenSSH `ssh-copy-id` workflow for installing an SSH public key on a remote host.

## Features

- Copies a public key to a remote server, mirroring OpenSSH `ssh-copy-id`'s behavior:
  - Default identity resolution: tries the SSH agent first (like `ssh-add -L`), then
    falls back to the most recently modified `~/.ssh/id*.pub` file
  - `-i` accepts an optional filename and auto-appends `.pub` if omitted
  - Skips keys already present on the remote `authorized_keys` file unless forced
- Supports force mode (`-f`) and dry-run mode (`-n`)
- Supports SFTP install mode (`-s`) for restricted-shell servers
- Best-effort passthrough of common `-o` SSH options (e.g. `StrictHostKeyChecking`,
  `UserKnownHostsFile`, `ConnectTimeout`, `IdentitiesOnly`, `Port`)
- Supports SSH config lookups and an alternative config file (`-F`)
- Accepts either `user host` or `user@host`
- Includes debug output for troubleshooting (`-x`)

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
python ssh-copy-id.py -s -p 2222 USER@HOST
python ssh-copy-id.py -o StrictHostKeyChecking=no USER@HOST
```

## Options

- `-h`, `--help` : show help
- `-f` : force mode -- copy keys without checking if they're already installed
- `-n` : dry run -- print the key(s) that would be installed
- `-s` : sftp mode -- install by downloading, editing, and re-uploading `authorized_keys`
- `-x` : debug output
- `-i [identity_file]` : use only the key(s) in `identity_file` (`.pub` appended if omitted);
  without `-i`, keys are taken from the SSH agent, falling back to the newest `~/.ssh/id*.pub`
- `-p` : port
- `-F` : alternative SSH config file
- `-o` : an `ssh -o`-style option (repeatable); a best-effort subset is honored
- `-t` : target path on the remote host (default `.ssh/authorized_keys`)

## Notes

This project mirrors the standard OpenSSH `ssh-copy-id` approach as closely as practical on top
of `paramiko`, since Windows has no bundled `ssh-copy-id`. A few things don't translate 1:1 from
the original shell script -- in particular, `-o` only recognizes a handful of common options
rather than being a raw passthrough to the `ssh` binary.
