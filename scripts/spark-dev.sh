#!/bin/sh
# Local acceptance stack for the blinded Spark desktop (regtest only).
#
#   scripts/spark-dev.sh up [--skip-helpers] [--skip-build]
#   scripts/spark-dev.sh down
#   scripts/spark-dev.sh status
#
# Only the native runner's own start/stop act on zark-spark-acceptance.
# `spark-regtest.py test` would reset that chain and `start`/`up` act on the
# development project, so neither is used here. Docker Desktop is never quit,
# and the container stops only after bitcoind has logged a clean shutdown.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
container=zark-spark-regtest
acceptance=zark-spark-acceptance
runner=/src/open-ssp/e2e/breez/target/debug/open-ssp-breez-e2e
state=.regtest/$acceptance/native
host_state=$repo/work/zark-spark/sources/open-ssp/$state
debug_log=$host_state/bitcoin/regtest/debug.log
tools=/src/open-ssp/.regtest/native-tools
helpers='zark-sdk-send zark-sdk-receive zark-ordinary-receive'

say() { echo "spark-dev: $*"; }
die() { echo "spark-dev: $*" >&2; exit 1; }
usage() {
  echo 'Usage: scripts/spark-dev.sh up [--skip-helpers] [--skip-build] | down | status' >&2
  exit 2
}

# Same resolution as the desktop launcher; spark-regtest.py honours it too.
if [ -n "${ZARK_SPARK_DOCKER:-}" ]; then
  docker=$ZARK_SPARK_DOCKER
elif [ -x /usr/local/bin/docker ]; then
  docker=/usr/local/bin/docker
else
  docker=$(command -v docker 2>/dev/null) || die 'Docker CLI not found; install Docker Desktop or set ZARK_SPARK_DOCKER.'
fi
case $docker in /*) [ -x "$docker" ] || die "Docker CLI $docker is not executable." ;; *) die 'ZARK_SPARK_DOCKER must be an absolute path.' ;; esac
export ZARK_SPARK_DOCKER="$docker"
command -v python3 >/dev/null 2>&1 || die 'python3 is required.'

regtest() { python3 "$repo/scripts/spark-regtest.py" "$@"; }
in_container() { "$docker" exec --user regtest "$container" "$@"; }
# Whole root leaves per denomination the SSP keeps, so Public can withdraw
# notes into Incognito through a swap. Regtest liquidity only.
ssp_ladder='{"10000":3,"5000":3,"2000":3}'
require_daemon() { "$docker" info >/dev/null 2>&1 || die 'Docker daemon unreachable. Start Docker Desktop first.'; }
container_state() { "$docker" inspect -f '{{.State.Running}}' "$container" 2>/dev/null || echo missing; }

# Prints the acceptance chain height, or nothing while RPC is not answering.
height() {
  # bitcoind.json records the exact bitcoind the runner started.
  bin=$(sed -n 's|.*"executable": *"\(/[^"]*\)/bitcoind".*|\1|p' "$host_state/bitcoind.json" 2>/dev/null | head -n 1)
  [ -n "$bin" ] || bin=$tools/bitcoin-29.0/bin
  value=$(in_container "$bin/bitcoin-cli" -datadir="/src/open-ssp/$state/bitcoin" -conf="/src/open-ssp/$state/bitcoin.conf" \
    getblockcount 2>/dev/null | tr -d '[:space:]') || true
  case $value in ''|*[!0-9]*) ;; *) echo "$value" ;; esac
}

# Read-only runner status: "<service>: running|stopped" lines come first; the
# SSP queries after them may fail when nothing listens, which is ignored.
services() {
  regtest exec "$runner" --project "$1" status 2>/dev/null | sed -n "s/^\\([a-z0-9-]*\\): $2\$/\\1/p" | tr '\n' ' ' || true
}

up() {
  skip_helpers=0
  skip_build=0
  for arg in "$@"; do
    case $arg in
      --skip-helpers) skip_helpers=1 ;;
      --skip-build) skip_build=1 ;;
      *) usage ;;
    esac
  done
  require_daemon
  # Both projects bind the same ports inside the container; never run them together.
  say 'checking that the development project zark-spark is stopped (read-only status)'
  dev=$(services zark-spark running)
  [ -z "$dev" ] || die "development project zark-spark is running (${dev% }). Stop it deliberately, then rerun."

  # Signer sockets left on the Docker Desktop shared mount by an earlier VM
  # session fail stat, unlink and bind with EOPNOTSUPP inside the container,
  # so the runner cannot replace them. Remove them from the host, only for
  # signers the runner positively reports stopped.
  stopped=$(services "$acceptance" stopped)
  sockets=$repo/work/zark-spark/sources/open-ssp/.regtest/native-sockets/$(printf %s "/src/open-ssp/$state" | shasum -a 256 | cut -c1-12)
  for i in 0 1 2; do
    case " $stopped " in
      *" signer-$i "*) [ ! -S "$sockets/$i.sock" ] || { say "removing stale $sockets/$i.sock"; rm -f "$sockets/$i.sock"; } ;;
    esac
  done

  say "starting $acceptance services (no reset)"
  regtest exec "$runner" --project "$acceptance" start

  say 'waiting for acceptance bitcoind RPC (up to 120 s)'
  waited=0
  current=$(height)
  while [ -z "$current" ]; do
    [ "$waited" -lt 120 ] || die "bitcoind RPC did not answer within 120 s; see python3 scripts/spark-regtest.py exec $runner --project $acceptance logs bitcoind"
    sleep 2
    waited=$((waited + 2))
    current=$(height)
  done
  say "acceptance bitcoind height $current"
  [ -f "$host_state/operators.json" ] || die "operators.json missing at $host_state; the acceptance project was never set up."

  if [ "$skip_helpers" = 0 ]; then
    say 'type-checking the SDK send driver'
    in_container python3 /integration/sdk/build.py --check-send
    say 'building zark-sdk-send, zark-sdk-receive and zark-ordinary-receive'
    in_container python3 /integration/sdk/build.py
    for helper in $helpers; do
      in_container test -x "$tools/$helper" || die "helper $tools/$helper missing after build"
    done
    say "helpers present in $tools"
  fi

  # The SSP pays swaps from leaves it holds. Incognito accepts only
  # wallet-created root leaves, which an SSP split never produces, so the
  # stack tops the SSP up with whole 10,000/5,000/2,000 roots.
  say "topping up SSP notes to $ssp_ladder"
  printf '{"op":"ssp_ladder","directory":"/src/open-ssp/%s","ladder":%s}\n' "$state" "$ssp_ladder" |
    "$docker" exec -i --user regtest -w /src/open-ssp/vendor/spark/spark "$container" \
      env ZARK_SPARK_ORDINARY_RECEIVE_FIXTURE=1 "$tools/zark-ordinary-receive" \
      '-test.run=^TestOrdinaryReceiveNativeFixture$' -test.timeout=20m 2>/dev/null |
    sed -n 's/^ZARK_FIXTURE_REPLY //p' | grep -q '"ok":true' || die 'SSP top-up failed; is the SSP running?'

  binary='<path printed by: node apps/desktop/runtime/spark/launch.mjs --blinded-build>'
  if [ "$skip_build" = 0 ]; then
    built=$("${ZARK_NODE:-node}" "$repo/apps/desktop/runtime/spark/launch.mjs" --blinded-build)
    printf '%s\n' "$built"
    binary=$(printf '%s\n' "$built" | sed -n 's/^ZARK_SPARK_DESKTOP_BINARY=//p')
    say 'building the desktop shell'
    CARGO_BUILD_JOBS=1 "${ZARK_SPARK_CARGO:-cargo}" build --locked --manifest-path apps/desktop-tauri/Cargo.toml --target-dir apps/desktop-tauri/target
  fi

  cat <<EOF

Ready. Open one window per profile (each in its own terminal):
  ZARK_SPARK_NETWORK=demo ./run-wallet.sh --blinded alice
  ZARK_SPARK_NETWORK=demo ./run-wallet.sh --blinded bob
Headless three-wallet check on a NEW network name:
  ZARK_SPARK_DESKTOP_BINARY=$binary node scripts/check-spark-blinded-desktop.mjs <new-network-name>
When finished:
  scripts/spark-dev.sh down
EOF
}

down() {
  [ $# -eq 0 ] || usage
  require_daemon
  if [ "$(container_state)" != true ]; then
    say "container $container is not running; nothing to stop"
    return 0
  fi
  # Skip the shutdown confirmation only when bitcoind is positively stopped;
  # an unreadable status still requires it.
  stopped=$(services "$acceptance" stopped)
  lines=0
  [ ! -f "$debug_log" ] || lines=$(wc -l < "$debug_log" | tr -d '[:space:]')

  say "stopping $acceptance services"
  regtest exec "$runner" --project "$acceptance" stop
  case " $stopped " in
    *' bitcoind '*) say 'acceptance bitcoind was already stopped; no shutdown to confirm' ;;
    *)
      # Only lines written after the stop began count as this shutdown.
      say 'waiting for bitcoind to log a clean shutdown (up to 120 s)'
      waited=0
      while :; do
        done_line=$(tail -n "+$((lines + 1))" "$debug_log" 2>/dev/null | grep -m 1 'Shutdown: done' || true)
        [ -z "$done_line" ] || break
        [ "$waited" -lt 120 ] || die "bitcoind did not log 'Shutdown: done' within 120 s. The container is left running; inspect $debug_log"
        sleep 2
        waited=$((waited + 2))
      done
      say "bitcoind: $done_line"
      ;;
  esac

  say "stopping container $container"
  regtest stop
  running=$(container_state)
  [ "$running" = false ] || die "container $container still reports Running=$running"
  say "container $container stopped"
}

status() {
  [ $# -eq 0 ] || usage
  if ! "$docker" info >/dev/null 2>&1; then
    say 'Docker daemon unreachable'
  else
    running=$(container_state)
    case $running in
      true) say "container $container: running" ;;
      false) say "container $container: stopped" ;;
      *) say "container $container: not created" ;;
    esac
    if [ "$running" = true ]; then
      current=$(height)
      say "acceptance bitcoind height: ${current:-not answering}"
    fi
  fi
  if [ -f "$host_state/operators.json" ]; then say 'acceptance operators.json: present'; else say 'acceptance operators.json: missing'; fi
  for helper in $helpers; do
    if [ -x "$repo/work/zark-spark/sources/open-ssp/.regtest/native-tools/$helper" ]; then
      say "helper $helper: present"
    else
      say "helper $helper: missing"
    fi
  done
}

action=${1:-}
if [ $# -gt 0 ]; then shift; fi
case $action in
  up) up "$@" ;;
  down) down "$@" ;;
  status) status "$@" ;;
  *) usage ;;
esac
