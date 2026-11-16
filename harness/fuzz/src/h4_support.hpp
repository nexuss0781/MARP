// MARP v2 — H4 FUZZ — file, digest and formatting helpers.
#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace marp::harness::h4 {

using u8 = std::uint8_t;

std::string sha256_hex(std::span<const u8> bytes);
std::string sha256_hex(std::string_view text);
std::string sha256_file(const std::filesystem::path& path);

bool read_file(const std::filesystem::path& path, std::vector<u8>& out);
bool write_file_atomic(const std::filesystem::path& path, std::span<const u8> bytes);
bool write_text_atomic(const std::filesystem::path& path, std::string_view text);

std::string trim_right(std::string text);

}  // namespace marp::harness::h4
