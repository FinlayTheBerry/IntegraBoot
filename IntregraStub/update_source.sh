#!/usr/bin/bash
# Updates the systemd folder to contain the latest source from the latest release on GitHub.

# Remove old source if it exists
rm -rf systemd

# Download the latest source tarball from GitHub
tarball_url="$(curl -s https://api.github.com/repos/systemd/systemd/releases/latest | jq -r ".tarball_url")"
curl -L "$tarball_url" -o systemd.tar.gz  --progress-bar

# Extract the source
tar -xf systemd.tar.gz
mv systemd-systemd-* systemd

# Remove the tarball since we don't need it anymore
rm systemd.tar.gz