#!/usr/bin/env bash
# Interactively create a login user. Run as root:
#   sudo deploy/create-user.sh
set -euo pipefail

[[ $EUID -eq 0 ]] || {
  echo "Run this as root: sudo $0" >&2
  exit 1
}
command -v adduser >/dev/null || {
  echo "adduser not found — this script targets Debian/Ubuntu." >&2
  exit 1
}

read -r -p "Username: " name
[[ $name =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || {
  echo "Invalid username: lowercase letters, digits, - and _, and it can't start with a digit." >&2
  exit 1
}
if id "$name" &>/dev/null; then
  echo "User '$name' already exists." >&2
  exit 1
fi

read -r -p "Give '$name' sudo? [y/N] " want_sudo

adduser "$name"        # prompts for the password and the optional name/phone fields

if [[ $want_sudo =~ ^[Yy]$ ]]; then
  usermod -aG sudo "$name"
  echo "Added '$name' to the sudo group."
fi

echo
echo "Created: $(id "$name")"
echo "To let them log in over SSH, put a public key in /home/$name/.ssh/authorized_keys"
echo "(owned by $name, dir 700, file 600)."
