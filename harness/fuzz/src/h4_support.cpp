// MARP v2 — H4 FUZZ — file, digest and formatting helpers.

#include "h4_support.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <system_error>

#include "mapr/e1_sha256.hpp"

namespace marp::harness::h4 {
namespace {

constexpr char kHex[] = "0123456789abcdef";

}  // namespace

std::string sha256_hex(std::span<const u8> bytes) {
    auto digest = mapr::Sha256::hash(
        std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()));
    if (!digest.ok()) return std::string(64, '0');
    std::string out;
    out.reserve(64);
    for (const u8 byte : digest.value()) {
        out.push_back(kHex[(byte >> 4u) & 0x0Fu]);
        out.push_back(kHex[byte & 0x0Fu]);
    }
    return out;
}

std::string sha256_hex(std::string_view text) {
    return sha256_hex(std::span<const u8>(
        reinterpret_cast<const u8*>(text.data()), text.size()));
}

std::string sha256_file(const std::filesystem::path& path) {
    std::vector<u8> bytes;
    if (!read_file(path, bytes)) return std::string(64, '0');
    return sha256_hex(std::span<const u8>(bytes.data(), bytes.size()));
}

bool read_file(const std::filesystem::path& path, std::vector<u8>& out) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size < 0) return false;
    stream.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(size), 0u);
    if (size > 0) {
        stream.read(reinterpret_cast<char*>(out.data()), size);
        if (!stream) return false;
    }
    return true;
}

bool write_file_atomic(const std::filesystem::path& path, std::span<const u8> bytes) {
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    const std::filesystem::path temporary = path.string() + ".tmp";
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) return false;
        if (!bytes.empty()) {
            stream.write(reinterpret_cast<const char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
        }
        if (!stream) return false;
    }
    std::filesystem::rename(temporary, path, error);
    if (error) {
        std::filesystem::remove(temporary, error);
        return false;
    }
    return true;
}

bool write_text_atomic(const std::filesystem::path& path, std::string_view text) {
    return write_file_atomic(
        path, std::span<const u8>(reinterpret_cast<const u8*>(text.data()), text.size()));
}

std::string trim_right(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    return text;
}

}  // namespace marp::harness::h4
