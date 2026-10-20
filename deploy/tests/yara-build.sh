#!/usr/bin/env bash
set -euo pipefail

# Optional native Agent build prerequisite. No installation or rule download is
# performed by the running Agent. Run with one build worker on each native OS.
build_root=${1:?usage: yara-build.sh OUTPUT_DIRECTORY}
mkdir -p "$build_root"
build_root=$(cd "$build_root" && pwd)
commit=84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8
digest=da7eb424e88360de6165d4af5fa88d6f72c22676f517d9d436a7cd67624b7119
archive="$build_root/yara-4.5.8.tar.gz"
if [[ ! -f "$archive" ]]; then
  curl --fail --silent --show-error --location --connect-timeout 15 --max-time 180 "https://codeload.github.com/VirusTotal/yara/tar.gz/$commit" -o "$archive"
fi
printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status
source_dir="$build_root/yara-$commit"
if [[ ! -d "$source_dir" ]]; then tar -xzf "$archive" -C "$build_root"; fi
cd "$source_dir"
# Keep the supported language/module surface identical on Linux and Windows.
# YARA otherwise registers hash via Windows Crypto even with --without-crypto.
sed -i '/^MODULE(hash)$/d' libyara/modules/module_list
./bootstrap.sh
configure_host=()
case "$(uname -s)" in MINGW*|MSYS*) configure_host=(--host=x86_64-w64-mingw32);; esac
./configure "${configure_host[@]}" --prefix="$build_root/install" --enable-static --disable-shared --without-crypto --disable-dotnet --disable-magic --disable-cuckoo --disable-macho --disable-dex CFLAGS="-O2"
make -j1
make install
test "$("$build_root/install/bin/yara" --version)" = '4.5.8'
printf '{"version":"4.5.8","commit":"%s","source_sha256":"%s","link":"static","crypto":false,"modules":"pe,elf,math,time,string,console,tests"}\n' "$commit" "$digest" > "$build_root/build.json"
