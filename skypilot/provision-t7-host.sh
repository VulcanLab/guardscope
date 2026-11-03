#!/usr/bin/env bash
# Provision the t7 re-check host (run ON the instance, user ubuntu).
# Actplane 0.1.8 loads only on kernel 6.17.x (targets/actplane/README.md);
# the stock noble image boots a newer kernel, so install the pinned -aws
# kernel, set grub to it, and reboot. Idempotent: re-run after the reboot;
# the second pass installs Docker and the python deps.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
KVER=6.17.0-1010-aws

if [ "$(uname -r)" != "$KVER" ]; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq "linux-image-$KVER" "linux-modules-$KVER" \
      "linux-modules-extra-$KVER"
  # pin grub to the 6.17 entry (persistent default)
  printf 'GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux %s"\n' \
      "$KVER" | sudo tee /etc/default/grub.d/99-t7-kernel.cfg
  sudo update-grub
  echo "rebooting into $KVER; RE-RUN THIS SCRIPT after the reboot"
  sleep 2
  sudo reboot
  exit 0
fi

echo "PROVISION STAGE 2: kernel $(uname -r) OK"
sudo apt-get update -qq
# docker engine + compose v2 plugin (runner shells out to plain `docker`)
sudo apt-get install -y -qq docker.io docker-compose-v2
sudo usermod -aG docker "$USER"
sudo systemctl enable --now docker
# python
sudo apt-get install -y -qq python3-venv python3-pip
sudo docker info >/dev/null
echo "PROVISION OK: kernel $(uname -r), docker up (new login needed for the docker group)"
