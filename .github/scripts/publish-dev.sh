#!/usr/bin/env bash
# Builds the Postgres 17 dev images on this machine and pushes them to ghcr.io/chelabase.
# It mirrors the dev-storage and dev-compute jobs of .github/workflows/images.yml (which is now
# only for tags and the platform images, run by hand).
#
#   .github/scripts/publish-dev.sh [--no-push | --push-only] [--only storage|compute]
#                                  [--allow-dirty] [--allow-unpushed] [--force-retag]
#
#   --no-push         build and test only; push nothing
#   --push-only       build nothing and run no variant test: push the images already built
#                     locally (images are built once, e.g. by an earlier --no-push run). Keeps
#                     every pre-check that applies to pushing (HEAD on origin/main, tag free,
#                     ghcr login, clean tree), and for each selected image requires the local
#                     ref to exist and its org.opencontainers.image.revision label (the build's
#                     full SHA) to equal HEAD; otherwise it refuses before pushing anything.
#                     Refused together with --no-push or --allow-unpushed.
#   --only NAME       build just the storage or the compute image (default: both)
#   --allow-dirty     build from a working tree with uncommitted changes
#   --allow-unpushed  build a HEAD that is not on origin/main (the image must not be pushed
#                     for real from such a commit: its <sha12> would not exist on the fork)
#   --force-retag     overwrite a tag that already exists in the registry (off by default:
#                     published tags are pinned by digest elsewhere)
#
# Images (linux/amd64, <sha12> = the first 12 hex of HEAD, the `neon_tag` of chelabase):
#   ghcr.io/chelabase/neon-storage:<sha12>-dev      root Dockerfile, PG_VERSIONS=v17
#   ghcr.io/chelabase/neon-compute-v17:<sha12>-dev  compute/compute-node.Dockerfile, v17, minimal
#
# Steps: pre-checks, build storage then compute (sequential: the builds are CPU-bound), run
# image_variant_test.sh on the storage image, then push both and print the pushed digests as
# ghcr.io/chelabase/<name>:<sha12>-dev@sha256:<digest>, ready to pin. Nothing is pushed unless
# every build and the variant test passed.
#
# Differences from images.yml: the push is a plain `docker push` of the locally built image, so
# the images carry no SBOM or provenance attestations, and the builds use the local builder
# cache, not the registry buildcache-dev tags.
#
# Requires docker, `docker login ghcr.io` for the push (the packages are public: pulling, as the
# builds do for the build-tools image, needs no login) and the four
# vendor/postgres-v1x submodules at their recorded commits (git submodule update --init).

REGISTRY_NS="ghcr.io/chelabase"
SOURCE_URL="https://github.com/chelabase/neon"

usage() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

die() {
    echo "publish-dev.sh: $*" >&2
    return 1
}

# parse_args <args...>: sets NO_PUSH, PUSH_ONLY, ONLY, ALLOW_DIRTY, ALLOW_UNPUSHED, FORCE_RETAG.
# Returns 2 for --help.
parse_args() {
    NO_PUSH=0
    PUSH_ONLY=0
    ONLY=""
    ALLOW_DIRTY=0
    ALLOW_UNPUSHED=0
    FORCE_RETAG=0
    while (($# > 0)); do
        case "$1" in
        --no-push) NO_PUSH=1; shift ;;
        --push-only) PUSH_ONLY=1; shift ;;
        --allow-dirty) ALLOW_DIRTY=1; shift ;;
        --allow-unpushed) ALLOW_UNPUSHED=1; shift ;;
        --force-retag) FORCE_RETAG=1; shift ;;
        --only)
            [[ $# -ge 2 ]] || { die "--only needs a value"; return 1; }
            case "$2" in
            storage | compute) ONLY="$2" ;;
            *) die "--only must be storage or compute, not '$2'"; return 1 ;;
            esac
            shift 2
            ;;
        -h | --help) usage; return 2 ;;
        *) die "unknown argument '$1'"; return 1 ;;
        esac
    done
    if ((PUSH_ONLY == 1 && NO_PUSH == 1)); then
        die "--push-only and --no-push contradict each other"
        return 1
    fi
    if ((PUSH_ONLY == 1 && ALLOW_UNPUSHED == 1)); then
        die "--push-only cannot be combined with --allow-unpushed (it only pushes images of a HEAD that is on origin/main)"
        return 1
    fi
}

# sha12 <full sha>
sha12() {
    echo "${1:0:12}"
}

# image_ref <storage|compute> <sha12>: the dev tag.
image_ref() {
    case "$1" in
    storage) echo "${REGISTRY_NS}/neon-storage:$2-dev" ;;
    compute) echo "${REGISTRY_NS}/neon-compute-v17:$2-dev" ;;
    *) die "unknown image '$1'" ;;
    esac
}

# build_tools_tag <repo root>: computed as build-tools.yml does.
build_tools_tag() {
    sha256sum "$1/build-tools/Dockerfile" | cut -c1-12
}

# submodules_ok <git submodule status output>: every submodule initialised and at the
# recorded commit (no '-', '+' or 'U' prefix), and at least one listed.
submodules_ok() {
    local line n=0
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        n=$((n + 1))
        case "${line:0:1}" in
        - | + | U) return 1 ;;
        esac
    done <<<"$1"
    ((n > 0))
}

# ghcr_login_present [docker config file]
ghcr_login_present() {
    local cfg="${1:-${DOCKER_CONFIG:-$HOME/.docker}/config.json}"
    [[ -f "$cfg" ]] || return 1
    grep -q '"ghcr.io"' "$cfg" || grep -q '"credsStore"' "$cfg"
}

# digest_from_inspect <docker buildx imagetools inspect output>
digest_from_inspect() {
    local d
    d="$(sed -n 's/^Digest:[[:space:]]*\(sha256:[0-9a-f]\{64\}\)[[:space:]]*$/\1/p' <<<"$1" | head -1)"
    [[ -n "$d" ]] || return 1
    echo "$d"
}

# pin_ref <tag ref> <digest>
pin_ref() {
    echo "$1@$2"
}

# tag_exists <ref>: true when the tag exists in the registry.
tag_exists() {
    docker buildx imagetools inspect "$1" >/dev/null 2>&1
}

# check_tag_free <ref>: fails when the tag exists, unless FORCE_RETAG=1.
check_tag_free() {
    if ((FORCE_RETAG == 1)); then return 0; fi
    if tag_exists "$1"; then
        die "the tag $1 already exists in the registry (published tags are pinned by digest elsewhere); pass --force-retag to overwrite it"
        return 1
    fi
}

fmt_time() {
    printf '%dm%02ds' $(($1 / 60)) $(($1 % 60))
}

# precheck: the repository and tool checks; fails with a message.
precheck() {
    command -v docker >/dev/null || { die "docker not found"; return 1; }
    if ((ALLOW_DIRTY == 0)) && [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
        die "the working tree is not clean (commit or stash, or pass --allow-dirty)"
        return 1
    fi
    git -C "$ROOT" fetch --quiet origin || { die "git fetch origin failed"; return 1; }
    if ((ALLOW_UNPUSHED == 0)) && ! git -C "$ROOT" merge-base --is-ancestor HEAD origin/main; then
        die "HEAD is not on origin/main: images must come from commits that exist on the fork (merge first, or pass --allow-unpushed with --no-push)"
        return 1
    fi
    if ((PUSH_ONLY == 0)) && ! submodules_ok "$(git -C "$ROOT" submodule status)"; then
        die "submodules are not initialised at the recorded commits (run: git submodule update --init)"
        return 1
    fi
    if ((NO_PUSH == 0)) && ! ghcr_login_present; then
        die "no ghcr.io login found in the docker config (pushing needs one even though the packages are public: docker login ghcr.io)"
        return 1
    fi
}

# image_revision <ref>: the full build SHA recorded in the local image's revision label (set by
# build_image); empty when the label is absent. Fails when the image does not exist locally.
image_revision() {
    docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$1" 2>/dev/null
}

# check_local_image <ref> <full sha>: the image exists locally and was built from that commit.
check_local_image() {
    local ref="$1" want="$2" got
    got="$(image_revision "$ref")" || {
        die "--push-only: the image $ref was not found locally (build it first: publish-dev.sh --no-push --allow-unpushed)"
        return 1
    }
    if [[ "$got" != "$want" ]]; then
        die "--push-only: the image $ref was built from '${got:-<no revision label>}', not from HEAD $want (rebuild, or check out the commit it was built from)"
        return 1
    fi
}

# build_image <storage|compute> <ref>
build_image() {
    local which="$1" ref="$2" start
    local common=(--platform linux/amd64 --load --provenance=false --sbom=false
        --label "org.opencontainers.image.source=${SOURCE_URL}"
        --label "org.opencontainers.image.revision=${SHA}"
        --tag "$ref")
    echo
    echo "##### build $which: $ref $(date '+%H:%M:%S')"
    start=$(date +%s)
    case "$which" in
    storage)
        docker buildx build "${common[@]}" \
            --build-arg PG_VERSIONS=v17 \
            --build-arg "REPOSITORY=${REGISTRY_NS}" \
            --build-arg IMAGE=neon-build-tools \
            --build-arg "TAG=$(build_tools_tag "$ROOT")" \
            --build-arg "GIT_VERSION=${SHA}" \
            --build-arg "BUILD_TAG=${SHA12}" \
            "$ROOT" || return 1
        ;;
    compute)
        docker buildx build "${common[@]}" \
            --file "$ROOT/compute/compute-node.Dockerfile" \
            --build-arg PG_VERSION=v17 \
            --build-arg EXTENSIONS=minimal \
            --build-arg DEBIAN_VERSION=bookworm \
            --build-arg "BUILD_TAG=${SHA12}" \
            "$ROOT" || return 1
        ;;
    esac
    BUILD_SECONDS="$(($(date +%s) - start))"
    echo "build $which took $(fmt_time "$BUILD_SECONDS") ($(docker image inspect --format '{{.Size}}' "$ref" | awk '{printf "%.0f MiB", $1/1048576}'))"
}

# push_image <ref>: pushes and prints the registry digest in the pin-ready form.
push_image() {
    local ref="$1" out digest
    docker push "$ref" || return 1
    out="$(docker buildx imagetools inspect "$ref")" || return 1
    digest="$(digest_from_inspect "$out")" || { die "could not read the digest of $ref"; return 1; }
    PINNED+=("$(pin_ref "$ref" "$digest")")
}

main() {
    set -euo pipefail
    local rc=0 which refs=() whiches=()
    parse_args "$@" || rc=$?
    if ((rc == 2)); then exit 0; elif ((rc != 0)); then usage; exit 1; fi

    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    precheck
    SHA="$(git -C "$ROOT" rev-parse HEAD)"
    SHA12="$(sha12 "$SHA")"

    if [[ -n "$ONLY" ]]; then whiches=("$ONLY"); else whiches=(storage compute); fi
    for which in "${whiches[@]}"; do
        refs+=("$(image_ref "$which" "$SHA12")")
        # Fail before the long builds, not after.
        if ((NO_PUSH == 0)); then check_tag_free "${refs[-1]}"; fi
    done
    echo "publish-dev: commit $SHA, images: ${refs[*]}, push=$((1 - NO_PUSH)), push-only=$PUSH_ONLY"

    local i
    if ((PUSH_ONLY == 1)); then
        # Check every image before pushing any.
        for i in "${!refs[@]}"; do
            check_local_image "${refs[$i]}" "$SHA" || exit 1
        done
    else
        for i in "${!whiches[@]}"; do
            build_image "${whiches[$i]}" "${refs[$i]}"
            if [[ "${whiches[$i]}" == storage ]]; then
                echo
                echo "##### image_variant_test.sh ${refs[$i]}"
                "$ROOT/.github/scripts/image_variant_test.sh" "${refs[$i]}" ||
                    { die "the storage image failed the variant test, nothing was pushed"; exit 1; }
            fi
        done
    fi

    if ((NO_PUSH == 1)); then
        echo
        echo "publish-dev: --no-push, built locally: ${refs[*]}"
        return 0
    fi

    PINNED=()
    for i in "${!refs[@]}"; do
        push_image "${refs[$i]}"
    done
    echo
    echo "Pushed. Pin these in chelabase (Compose defaults NEON_IMAGE and COMPUTE_NODE_IMAGE):"
    printf '  %s\n' "${PINNED[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
