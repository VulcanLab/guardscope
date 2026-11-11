#!/usr/bin/env bash
# Provision the agentgateway campaign host (run ON the instance, user ubuntu).
# Stock kernel: Tracee runs on the stock noble 7.x -aws kernel (verified in
# the m1/m2 campaigns on the same AMI family); only the t7 actplane engine
# needs the 6.17.x pin and this campaign runs only t1 bindings, so there is
# NO kernel stage — this is provision-t7-host.sh stage 2 adapted, plus the
# m2 docker-log-bounds lesson applied up front.
# Idempotent: safe to re-run.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -qq

# docker log bounds FIRST (the m2 disk-fill lesson: an unbounded tracee
# container log filled the root disk mid-campaign). 4g x 2 = the m2 setting;
# a per-run force-recreated tracee emits at most a few hundred MB, so the
# bound is a safety valve, never hit inside a run's capture.
if [ ! -f /etc/docker/daemon.json ]; then
  sudo mkdir -p /etc/docker
  printf '{\n  "log-driver": "json-file",\n  "log-opts": { "max-size": "4g", "max-file": "2" }\n}\n' \
    | sudo tee /etc/docker/daemon.json
fi

# docker engine + compose v2 plugin (the runner shells out to plain
# `docker compose`), then python for the guardscope venv.
sudo apt-get install -y -qq docker.io docker-compose-v2 python3-venv python3-pip
sudo usermod -aG docker "$USER"
sudo systemctl enable --now docker
sudo systemctl restart docker   # pick up daemon.json if docker pre-existed it
sudo docker info >/dev/null
echo "PROVISION OK: kernel $(uname -r), docker up (new login needed for the docker group)"
