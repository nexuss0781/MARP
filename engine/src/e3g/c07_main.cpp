// MARP v2 — C07 WIRE — gate entry point.
//
// Kept in its own translation unit so the harness can be linked into a test
// binary without a `main` clash.

#include "c07_checks.hpp"

int main(int argc, char** argv) { return c07::run_main(argc, argv); }
