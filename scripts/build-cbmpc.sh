#!/bin/sh
# Builds the pinned cb-mpc ECDSA-2P library, with scripts/cbmpc-blind-sign.patch
# applied, and its static OpenSSL into the ignored work/cbmpc prefix consumed by
# integrations/spark/ecdsa-2p. Artifacts are host builds and are never
# committed; BUILD-INFO records the patch and library digests so the Rust build
# refuses a prefix that was rebuilt, unpatched or replaced afterwards.
#
# The build is staged in work/cbmpc-blind and replaces work/cbmpc only after it
# succeeds, so a failed rebuild leaves the previous prefix usable.
#
#   sh scripts/build-cbmpc.sh            # clone cb-mpc from GitHub
#   CBMPC_SOURCE=/path/to/clone sh scripts/build-cbmpc.sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cbmpc_commit=0b716706f998633912ee2be9b9bf8909aed66088
openssl_version=3.6.4
openssl_sha256=9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef
patch_name=cbmpc-blind-sign.patch
patch_file="$root/scripts/$patch_name"
prefix="$root/work/cbmpc"
staged="$root/work/cbmpc-blind"
build="$root/work/cbmpc-blind-build"
jobs="${JOBS:-4}"

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)
        openssl_target=darwin64-arm64-cc
        # System libc++ only: a Homebrew LLVM build references symbols that
        # macOS's /usr/lib/libc++ lacks. Both libraries share one target.
        CC=/usr/bin/clang CXX=/usr/bin/clang++
        MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
        export MACOSX_DEPLOYMENT_TARGET ;;
    Linux-x86_64) openssl_target=linux-x86_64; CC="${CC:-clang}" CXX="${CXX:-clang++}" ;;
    Linux-aarch64) openssl_target=linux-aarch64; CC="${CC:-clang}" CXX="${CXX:-clang++}" ;;
    *) echo "unsupported cb-mpc host $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
export CC CXX

patch_sha256=$(shasum -a 256 "$patch_file" | cut -d' ' -f1)
rm -rf "$build" "$staged"
trap 'rm -rf "$build" "$staged"' EXIT
mkdir -p "$build" "$staged/lib"
cd "$build"

tarball="openssl-$openssl_version.tar.gz"
curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-$openssl_version/$tarball" -o "$tarball"
echo "$openssl_sha256  $tarball" | shasum -a 256 -c -
tar -xzf "$tarball"
(
    cd "openssl-$openssl_version"
    # Same source patch and Configure flags as cb-mpc's scripts/openssl builds.
    sed -i.orig -e 's/^static//' crypto/ec/curve25519.c
    ./Configure -static -DOPENSSL_THREADS no-shared \
        no-afalgeng no-apps no-aria no-autoload-config no-bf no-camellia no-cast no-chacha no-cmac no-cms no-crypto-mdebug \
        no-comp no-cmp no-ct no-des no-dh no-dgram no-dsa no-dso no-dtls no-dynamic-engine no-ec2m no-egd no-engine no-external-tests \
        no-gost no-http no-idea no-mdc2 no-md2 no-md4 no-module no-nextprotoneg no-ocb no-ocsp no-psk no-padlockeng no-poly1305 \
        no-quic no-rc2 no-rc4 no-rc5 no-rfc3779 no-scrypt no-sctp no-seed no-siphash no-sm2 no-sm3 no-sm4 no-sock no-srtp no-srp \
        no-ssl-trace no-ssl3 no-stdio no-tests no-tls no-ts no-unit-test no-uplink no-whirlpool no-zlib \
        --prefix="$build/openssl" --libdir=lib "$openssl_target"
    make -j"$jobs" >/dev/null
    make install_sw >/dev/null
)

git clone --quiet "${CBMPC_SOURCE:-https://github.com/coinbase/cb-mpc}" cb-mpc
git -C cb-mpc -c advice.detachedHead=false checkout --quiet "$cbmpc_commit"
test "$(git -C cb-mpc rev-parse HEAD)" = "$cbmpc_commit"
(
    cd cb-mpc
    patch -p1 --forward --quiet < "$patch_file"
    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF \
        -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
        ${MACOSX_DEPLOYMENT_TARGET:+-DCMAKE_OSX_DEPLOYMENT_TARGET=$MACOSX_DEPLOYMENT_TARGET} \
        -DCBMPC_OPENSSL_ROOT="$build/openssl" >/dev/null
    cmake --build build -j"$jobs" >/dev/null
    scripts/install.sh --mode public --prefix "$build/install" >/dev/null
)

cp "$build/install/lib/libcbmpc.a" "$build/openssl/lib/libcrypto.a" "$staged/lib/"
cp -R "$build/install/include" "$staged/include"
{
    echo "cb-mpc $cbmpc_commit"
    echo "openssl $openssl_version $openssl_sha256"
    echo "patch $patch_name $patch_sha256"
    echo "host $(uname -s)-$(uname -m) ${MACOSX_DEPLOYMENT_TARGET:-}"
    (cd "$staged/lib" && shasum -a 256 libcbmpc.a libcrypto.a)
} > "$staged/BUILD-INFO"
rm -rf "$build"
rm -rf "$prefix.previous"
if [ -e "$prefix" ]; then mv "$prefix" "$prefix.previous"; fi
mv "$staged" "$prefix"
rm -rf "$prefix.previous"
cat "$prefix/BUILD-INFO"
