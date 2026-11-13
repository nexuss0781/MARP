// =====================================================================
//  MARP  ::  Stage 2  ::  MAU Translator  ::  mau_translate.cpp
//
//  Implementation lives in mapr::ir_v2.cpp (single translation unit,
//  avoiding ODR duplicates with ir_v2.o). This file is retained for
//  build-graph compatibility; the translator contract is implemented
//  in ir_v2.cpp with exact decimal BigInt parameters.
// =====================================================================

#include "mapr/mau_translate.hpp"
#include "mapr/ir_v2.hpp"
