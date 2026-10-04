#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# dede build / run / install helper.
#
#   ./build.sh [deps] [--with-gui]     configure + build (deps = install packages first)
#   ./build.sh test                    build + run the test suite
#   ./build.sh run [file] [args...]    build + launch the terminal shell
#   ./build.sh gui [file]              build (GUI) + launch the Vulkan UI
#   ./build.sh demo                    build + run the decrypt showcase
#   ./build.sh bench                   build + run the micro-benchmark
#   ./build.sh install [prefix]        install binaries (default: /usr/local)
#   ./build.sh clean                   remove the build directory
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD="$ROOT/build"
IMGUI_DIR="$ROOT/third_party/imgui"
WITH_GUI=0
GEN="Unix Makefiles"; BUILDER="make"
command -v ninja >/dev/null 2>&1 && { GEN="Ninja"; BUILDER="ninja"; }

for a in "$@"; do [ "$a" = "--with-gui" ] && WITH_GUI=1; done

say() { printf '\033[1;36m[dede]\033[0m %s\n' "$*"; }

install_deps() {
  say "installing build dependencies (needs sudo)"
  sudo apt-get update -q
  sudo apt-get install -y -q build-essential cmake ninja-build clang libcapstone-dev
  if [ "$WITH_GUI" = "1" ]; then
    sudo apt-get install -y -q libvulkan-dev libglfw3-dev glslang-tools vulkan-validationlayers
  fi
}

fetch_imgui() {
  if [ ! -f "$IMGUI_DIR/imgui.cpp" ]; then
    say "fetching Dear ImGui (docking branch) into third_party/imgui"
    git clone --depth 1 --branch docking https://github.com/ocornut/imgui.git "$IMGUI_DIR"
  fi
}

configure() {
  local args=(-S "$ROOT" -B "$BUILD" -G "$GEN" -DCMAKE_BUILD_TYPE=Release)
  if [ "$WITH_GUI" = "1" ]; then fetch_imgui; args+=(-DDEDE_WITH_GUI=ON); fi
  say "configuring ($GEN)"
  cmake "${args[@]}"
}

build() { configure; say "building"; cmake --build "$BUILD" -j"$(nproc)"; }

cmd="${1:-build}"
case "$cmd" in
  deps)    install_deps; shift || true; [ $# -gt 0 ] && exec "$0" "$@" ;;
  build|--with-gui) build; say "done -> $BUILD/dede" ;;
  test)    build; say "running tests"; ctest --test-dir "$BUILD" --output-on-failure ;;
  run)     build; shift; exec "$BUILD/dede" "$@" ;;
  gui)     WITH_GUI=1; build; shift; exec "$BUILD/dede-gui" "$@" ;;
  demo)    build; exec "$BUILD/dede-decrypt-demo" ;;
  bench)   build; exec "$BUILD/dede-bench" ;;
  install)
    build
    prefix="${2:-/usr/local}"
    say "installing to $prefix/bin"
    install -d "$prefix/bin"
    install -m755 "$BUILD/dede" "$prefix/bin/dede"
    install -m755 "$BUILD/dede-decrypt-demo" "$prefix/bin/dede-decrypt-demo"
    [ -f "$BUILD/dede-gui" ] && install -m755 "$BUILD/dede-gui" "$prefix/bin/dede-gui"
    say "installed" ;;
  clean)   say "removing $BUILD"; rm -rf "$BUILD" "$ROOT/build-gui" ;;
  *) echo "unknown command: $cmd"; sed -n '3,18p' "$0"; exit 1 ;;
esac
