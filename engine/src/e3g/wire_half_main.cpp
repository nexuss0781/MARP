// MARP v2 — E3 WIRE — E3-G — wire-half isolation probe.
//
// A binary whose only purpose is to be inspected: it links E1 + E2 + C07 + the
// wire-side harness and *no* C08 object, so `nm` on it proves that the legacy
// decoder is absent from the v2 side.  It prints the corpus size and exits; the
// derivation below forces the wire-side symbols into the link so the symbol table
// is not optimised down to nothing.

#include <cstdio>

#include "e3g_checks.hpp"

int main(int argc, char** argv) {
    e3g::Settings settings;
    if (argc > 1) settings.root = argv[1];
    const e3g::Corpus corpus = e3g::build_corpus(settings.root);
    std::printf("wire half: canon=%zu noncanon=%zu hand_built=%zu fuzz=%zu\n",
                corpus.canon.size(), corpus.noncanon.size(), corpus.hand_built.size(),
                corpus.fuzz_seeds.size());
    return 0;
}
