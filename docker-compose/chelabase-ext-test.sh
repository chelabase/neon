#!/usr/bin/env bash
#
# Extension-test harness wrapper.
#
# Builds the compute image (EXTENSIONS=all by default; --extensions minimal for the minimal compute) and the `extension-tests` image from this checkout,
# tags what docker-compose/docker-compose.yml expects, and runs docker_compose_test.sh on them
# for Postgres 17. `publish-dev.sh` builds only EXTENSIONS=minimal, so it cannot feed this harness.
#
# The harness also needs the storage image (`${REPOSITORY}/neon:${TAG}`: pageserver, safekeeper,
# storage broker, storage controller). The wrapper never builds it; pass the one `publish-dev.sh`
# built from the same commit with --storage-image.
#
# Nothing built here is meant for publishing.

set -uo pipefail

REPOSITORY=chelabase-local
PG_VERSION=v17
DEBIAN_VERSION=bookworm

usage() {
    cat <<'EOF'
usage: chelabase-ext-test.sh [--extensions minimal|all] [--storage-image <ref>] [--only <dir,...>] [--keep-images <tag>] [--help]

  --extensions minimal|all  extensions of the compute and the tests image (default all); minimal builds
                         the slim extension-tests-minimal image (timescaledb, pg_partman, pg_cron)
  --storage-image <ref>  tag <ref> as chelabase-local/neon:<tag> for the harness's storage services;
                         that retag is removed afterwards (unless --keep-images); <ref> is kept
  --only <dir,...>       run only these docker-compose/ext-src directories (contrib suite skipped)
  --keep-images <tag>    use <tag> instead of ext-test and keep every image afterwards
  --help                 print this text

Builds the compute (EXTENSIONS=all, or minimal) and extension-tests images from this checkout, runs
docker_compose_test.sh for Postgres 17 on them, then takes the harness's containers down (best
effort, also with --keep-images) and removes the images (unless --keep-images).
The exit status is the harness's.
EOF
}

die_usage() {
    echo "chelabase-ext-test.sh: $*" >&2
    usage >&2
    exit 2
}

extensions="all"
storage_image=""
only=""
keep_tag=""

# need_value <flag> <args...>: dies unless the first of <args> exists, is not empty and does not look like a flag.
need_value() {
    local flag="$1"
    shift
    [[ $# -ge 1 ]] || die_usage "$flag needs a value"
    [[ -n "$1" ]] || die_usage "$flag needs a non-empty value"
    [[ "$1" != -* ]] || die_usage "$flag needs a value, got the flag-looking '$1'"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
    --help | -h)
        usage
        exit 0
        ;;
    --storage-image)
        shift
        need_value --storage-image "$@"
        storage_image="$1"
        ;;
    --only)
        shift
        need_value --only "$@"
        # The same names run-tests.sh takes (^[A-Za-z0-9._-]+$, never `.` or `..`),
        # checked here so a bad list fails before any build.
        [[ "$1" =~ ^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$ ]] ||
            die_usage "--only takes comma-separated directory names ([A-Za-z0-9._-]), got '$1'"
        IFS=, read -r -a only_entries <<<"$1"
        for entry in "${only_entries[@]}"; do
            [[ "$entry" != . && "$entry" != .. ]] ||
                die_usage "--only can't name '$entry'"
        done
        only="$1"
        ;;
    --keep-images)
        shift
        need_value --keep-images "$@"
        keep_tag="$1"
        ;;
    --extensions)
        shift
        need_value --extensions "$@"
        case "$1" in
        minimal | all) extensions="$1" ;;
        *) die_usage "--extensions must be 'minimal' or 'all', got '$1'" ;;
        esac
        ;;
    -*)
        die_usage "unknown flag '$1'"
        ;;
    *)
        die_usage "unexpected argument '$1'"
        ;;
    esac
    shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TAG="${keep_tag:-ext-test}"
compute_image="$REPOSITORY/compute-node-$PG_VERSION:$TAG"
tests_image="$REPOSITORY/neon-test-extensions-$PG_VERSION:$TAG"
storage_tag="$REPOSITORY/neon:$TAG"

if [[ -z "$storage_image" ]]; then
    echo "chelabase-ext-test.sh: warning: no --storage-image; the harness's storage services use $storage_tag, which must already exist locally" >&2
fi

harness_started=false

cleanup() {
    local rc=$?
    # The harness's own `down` doesn't run when it is interrupted or fails early: take its
    # project down (best effort) before removing the images its containers use.
    # --remove-orphans: a parallel run's compute2..N (docker-compose-parallel.yml) aren't
    # in docker-compose.yml.
    if $harness_started; then
        REPOSITORY="$REPOSITORY" TAG="$TAG" docker compose \
            -f "$ROOT/docker-compose/docker-compose.yml" --profile test-extensions \
            down --remove-orphans || true
    fi
    if [[ -z "$keep_tag" ]]; then
        local images=("$compute_image" "$tests_image")
        [[ -n "$storage_image" ]] && images+=("$storage_tag")
        docker rmi "${images[@]}" || true
    fi
    exit "$rc"
}
trap cleanup EXIT

build() {
    # build <extra docker build args...>; the context is the checkout root.
    docker build \
        --file "$ROOT/compute/compute-node.Dockerfile" \
        --build-arg "PG_VERSION=$PG_VERSION" \
        --build-arg "EXTENSIONS=$extensions" \
        --build-arg "DEBIAN_VERSION=$DEBIAN_VERSION" \
        --build-arg "BUILD_TAG=$TAG" \
        "$@" \
        "$ROOT"
}

build --tag "$compute_image" || exit 1
tests_target=extension-tests
[[ "$extensions" == minimal ]] && tests_target=extension-tests-minimal
build --target "$tests_target" --tag "$tests_image" || exit 1

if [[ -n "$storage_image" ]]; then
    docker tag "$storage_image" "$storage_tag" || exit 1
fi

harness_started=true
TEST_VERSION_ONLY=17 ONLY="$only" REPOSITORY="$REPOSITORY" TAG="$TAG" \
    "$ROOT/docker-compose/docker_compose_test.sh"
exit $?
