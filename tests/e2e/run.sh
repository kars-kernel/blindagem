#!/usr/bin/env bash
# End to end, in the two steps a real administrator takes:
#   1. apply the generated playbook   -> the automated findings go away
#   2. do the manual step it listed   -> the critical finding goes away and the score moves
set -euo pipefail
trap 'docker rm -f blindagem-e2e >/dev/null 2>&1 || true' EXIT

docker run -d --name blindagem-e2e blindagem-weak
docker exec blindagem-e2e blindagem audit --json --profile container > before.json
docker exec blindagem-e2e blindagem fix --profile container -o /tmp/fix.yml
docker cp blindagem-e2e:/tmp/fix.yml fix.yml

ansible-lint fix.yml

# kernel and net are skipped: /proc/sys is read-only inside a container and there is
# no service manager, hence skip_service_restart. The lock-out guard is bypassed
# because this container has no authorized_keys and no SSH session to lose.
ansible-playbook -i blindagem-e2e, -c community.docker.docker fix.yml \
  --skip-tags kernel,net \
  -e skip_service_restart=true \
  -e blindagem_allow_lockout=true

docker exec blindagem-e2e blindagem audit --json --profile container > after.json
echo "== after the playbook =="
python3 tests/e2e/assert_improved.py before.json after.json

# The playbook deliberately refuses to delete accounts, so the report lists it as
# manual work. Doing it here proves the report's manual steps are the real remainder.
echo "== after the manual step the report asked for =="
docker exec blindagem-e2e sed -i '/^toor:/d' /etc/passwd
docker exec blindagem-e2e blindagem audit --json --profile container > after-manual.json
python3 tests/e2e/assert_improved.py before.json after-manual.json --expect-higher-score
