#!/usr/bin/env bash
# Builds the five files of a bus release from one commit of this repository.
#
# Both builders run this same script in the same container image: the build on GitHub's runner and
# the second build on the publisher's own computer. A release is signed only when the two produce
# the same bytes, so neither builder has to be believed on its own.
#
#   build_release.sh <commit> <output directory>
#
# Run from a clean clone, anywhere inside it. Needs git, curl, tar and sha256sum. Everything else
# is fetched here and checked against a hash kept in the source.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: build_release.sh <commit> <output directory>" >&2
    exit 2
fi
commit="$1"
output="$2"

repository="$(git rev-parse --show-toplevel)"
bus="$repository/bus"
cd "$bus"

if [ "$(git rev-parse HEAD)" != "$commit" ]; then
    echo "this checkout is not at $commit" >&2
    exit 1
fi
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
    echo "this checkout has changes or stray files; build from a clean clone" >&2
    exit 1
fi
if [ -e "$output" ]; then
    echo "$output already exists; the output directory must be new" >&2
    exit 1
fi

tree="$(git rev-parse "$commit^{tree}")"
SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$commit")"
export SOURCE_DATE_EPOCH

# The one uv this release is built with and carries. Its version and hash are in the source, where
# the installed verifier also reads them.
pinned() {
    python_name="$1"
    sed -n "/^$python_name = /,/^\$/p" src/strugglebus/release_validation.py | tr -d ' ()\n' \
        | sed -n 's/^[A-Z_0-9]*="\([^"]*\)"$/\1/p'
}
uv_version="$(pinned UV_VERSION)"
uv_hash="$(pinned UV_ARCHIVE_SHA256)"
if [ -z "$uv_version" ] || [ "${#uv_hash}" -ne 64 ]; then
    echo "could not read the pinned uv version and hash from the source" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="$work/uv.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-time 300 \
    --output "$archive" \
    "https://github.com/astral-sh/uv/releases/download/$uv_version/uv-x86_64-unknown-linux-gnu.tar.gz"
echo "$uv_hash  $archive" | sha256sum --check --status || {
    echo "the downloaded uv is not the pinned one" >&2
    exit 1
}
mkdir "$work/uv"
tar -xzf "$archive" -C "$work/uv" --strip-components=1
uv="$work/uv/uv"

# Nothing the build writes may land in the checkout, or the clean check inside it would fail.
export UV_PROJECT_ENVIRONMENT="$work/venv"
export UV_CACHE_DIR="$work/cache"
export UV_PYTHON_INSTALL_DIR="$work/python"
export UV_NO_PROGRESS=1

"$uv" python install 3.13
"$uv" sync --locked --all-extras
"$uv" run python scripts/check_requirements_lock.py
"$uv" build --wheel --out-dir "$work/dist"
"$uv" run python scripts/validate_release_artifacts.py "$work/dist"

version="$("$uv" run python -c 'import strugglebus; print(strugglebus.__version__)')"
wheel="strugglebus-$version-py3-none-any.whl"
mkdir "$work/canonical"
"$uv" run python scripts/canonical_wheel.py normalize "$work/dist/$wheel" "$work/canonical/$wheel"

# Inside a release its tag is vX.Y.Z. In this repository the tag is bus/vX.Y.Z, and it is made
# only when the release is published, because the tag carries the publisher's signature.
"$uv" run python scripts/release_bundle.py build \
    --repository "$bus" \
    --dist "$work/canonical" \
    --output "$output" \
    --tag "v$version" \
    --expected-commit "$commit" \
    --expected-tree "$tree" \
    --uv-binary "$uv" \
    --source-repository u64a/strugglebus \
    --pre-tag > /dev/null

"$uv" run python scripts/canonical_wheel.py verify "$output/$wheel" --source-date-epoch "$SOURCE_DATE_EPOCH"
"$uv" run python scripts/release_bundle.py validate "$output" \
    --expected-repository u64a/strugglebus \
    --expected-tag "v$version" \
    --expected-commit "$commit" \
    --expected-tree "$tree" > /dev/null

echo "bus $version from $commit"
(cd "$output" && sha256sum -- * | sort -k 2)
