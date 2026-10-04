// SPDX-License-Identifier: Apache-2.0
//
// dede-forge: write the five tutorial tiers to disk as flat x86-64 blobs
// (tier1.bin .. tier5.bin) that you load into dede. See docs/TUTORIAL.md.
#include <cstdio>
#include <fstream>
#include <string>

#include "dede/samples/tiers.hpp"

using namespace dede;

int main(int argc, char** argv) {
    std::string dir = argc >= 2 ? argv[1] : ".";
    for (int n = 1; n <= samples::kTierCount; ++n) {
        auto t = samples::make_tier(n);
        std::string path = dir + "/tier" + std::to_string(n) + ".bin";
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(t.image.data()),
                static_cast<std::streamsize>(t.image.size()));
        std::printf("tier %d  %-34s  %5zu bytes  -> %s\n", n, t.name.c_str(), t.image.size(), path.c_str());
        std::printf("         teaches: %s\n", t.teaches.c_str());
    }
    std::printf("\nLoad one with:  dede %s/tier1.bin   (then type 'help')\n", dir.c_str());
    return 0;
}
