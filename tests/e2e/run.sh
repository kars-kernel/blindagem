#!/usr/bin/env bash
# End to end: audit the weak container, apply the generated playbook, audit again.
# The score has to go up and nothing that passed may start failing.
set -euo pipefail
trap 'docker rm -f blindagem-e2e >/dev/null 2>&1 || true' EXIT

docker run -d --name blindagem-e2e blindagem-weak
docker exec blindagem-e2e blindagem audit --json --profile container > before.json
docker exec blindagem-e2e blindagem fix --profile container -o /tmp/fix.yml
docker cp blindagem-e2e:/tmp/fix.yml fix.yml

ansible-lint fix.yml

# kernel and net are skipped: /proc/sys is read-only inside a container, and there is
# no service manager, hence skip_service_restart.
ansible-playbook -i blindagem-e2e, -c community.docker.docker fix.yml \
  --skip-tags kernel,net \
  -e skip_service_restart=true \
  -e blindagem_allow_lockout=true

docker exec blindagem-e2e blindagem audit --json --profile container > after.json
python3 tests/e2e/assert_improved.py before.json after.json
