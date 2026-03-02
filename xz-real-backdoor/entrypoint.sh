#!/bin/sh

# This entrypoint is a simulation system with backdoor CVE-2024-3094 (backdoor xz/liblzma).
# First we need start systemd, and start with systemd sshd service.

# Start systemd
/lib/systemd/systemd

# Start sshd service
systemctl start sshd
