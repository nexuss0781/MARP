#include "marp/harness/fixtures.hpp"

#include <mapr/e1_sha256.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;
using namespace marp::harness;

namespace {

enum class Command {
    Generate,
    Verify,
    Stream,
    Range,
    Materialize,
    List,
    RecordCheck,
    RecordSmall,
    VerifyEvidence
};

void usage(const char* program) {
    std::cerr
        << "Usage: " << program << " [options]\n"
        << "  --root <repo> --out <dir> --manifest <path> [--real <path>] [--coded <path>] [--allow-blocked]\n"
        << "  --verify --manifest <path> [--allow-blocked] [--evidence]\n"
        << "  --stream <id> [--sha256]\n"
        << "  --range <id> <offset> <len>\n"
        << "  --materialize <id> --to <path>\n"
        << "  --list\n"
        << "Evidence helpers used by CI:\n"
        << "  --evidence [--determinism] [--ci-run-id id] [--ci-run-url url] [--commit sha] [--runner-os name]\n"
        << "  --record-check <check> <item> <expected> <actual> <input_sha256> <verdict>\n"
        << "  --record-small <id> --file <path> --external-sha <sha256>\n"
        << "  --verify-evidence\n";
}

std::string command_line(int argc, char** argv) {
    std::string line;
    for (int i = 0; i < argc; ++i) {
        if (i != 0) line.push_back(' ');
        line += argv[i];
    }
    return line;
}

BigInt parse_bigint(std::string_view text) {
    auto result = BigInt::from_decimal(text);
    if (!result.ok()) throw std::invalid_argument("invalid decimal integer: " + std::string(text));
    return std::move(result).value();
}

EvidenceContext context_from(const GenerateOptions& options) {
    EvidenceContext context;
    context.root = options.root;
    context.manifest = options.manifest;
    context.command_line = options.command_line;
    context.ci_run_id = options.ci_run_id;
    context.ci_run_url = options.ci_run_url;
    context.commit = options.commit;
    context.runner_os = options.runner_os;
    return context;
}

void require_value(int argc, char** /*argv*/, int& i, const std::string& option) {
    if (i + 1 >= argc) throw std::invalid_argument("missing value for " + option);
    ++i;
}

int stream_command(const std::string& id, bool digest_only, const GenerateOptions& options) {
    const auto specs = catalogue(options);
    const FixtureSpec* spec = nullptr;
    for (const auto& candidate : specs) {
        if (candidate.id == id) spec = &candidate;
    }
    if (spec == nullptr) throw std::invalid_argument("unknown fixture id");
    if (spec->mode == FixtureMode::Virtual) {
        throw std::invalid_argument("virtual fixtures reject --stream; use --range");
    }
    auto stream = open_stream(id, options);
    std::array<std::uint8_t, 64 * 1024> buffer{};
    mapr::Sha256 ctx;
    std::uint64_t total = 0;
    while (true) {
        const std::size_t got = stream->read(std::span<std::uint8_t>(buffer));
        if (got == 0) break;
        const auto err = ctx.update(std::string_view(
            reinterpret_cast<const char*>(buffer.data()), got));
        if (err != mapr::ErrCode::Ok) throw std::runtime_error("SHA-256 update failed");
        total += static_cast<std::uint64_t>(got);
        if (!digest_only) {
            std::cout.write(reinterpret_cast<const char*>(buffer.data()),
                            static_cast<std::streamsize>(got));
            if (!std::cout) throw std::runtime_error("stdout write failed");
        }
    }
    if (spec->mode == FixtureMode::Generated && BigInt(total) != spec->bytes) {
        throw std::runtime_error("stream length mismatch");
    }
    if (digest_only) {
        auto digest = ctx.finish();
        if (!digest.ok()) throw std::runtime_error("SHA-256 finish failed");
        std::cout << digest_hex(digest.value()) << "\n";
    }
    return 0;
}

int range_command(const std::string& id, const BigInt& offset, const BigInt& length,
                  const GenerateOptions& options) {
    constexpr std::size_t chunk = 64 * 1024;
    BigInt remaining = length;
    BigInt position = offset;
    while (!remaining.is_zero()) {
        const auto checked = remaining.to_u64_checked();
        const std::size_t want = checked.has_value() && checked.value() < chunk
                                     ? static_cast<std::size_t>(checked.value())
                                     : chunk;
        const auto bytes = read_range(id, position, want, options);
        std::cout.write(reinterpret_cast<const char*>(bytes.data()),
                        static_cast<std::streamsize>(bytes.size()));
        if (!std::cout) throw std::runtime_error("stdout write failed");
        const BigInt advanced(static_cast<std::uint64_t>(want));
        position = [&] {
            auto result = position.add(advanced);
            if (!result.ok()) throw std::runtime_error("range offset overflow");
            return std::move(result).value();
        }();
        remaining = [&] {
            auto result = remaining.sub(advanced);
            if (!result.ok()) throw std::runtime_error("range length underflow");
            return std::move(result).value();
        }();
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    GenerateOptions options;
    options.root = fs::current_path();
    options.command_line = command_line(argc, argv);
    Command command = Command::Generate;
    std::string id;
    std::string to;
    std::string file;
    std::string external_sha;
    BigInt offset;
    BigInt length;
    bool sha256 = false;
    std::vector<std::string> record_args;

    try {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--help") {
                usage(argv[0]);
                return 0;
            } else if (arg == "--root") {
                require_value(argc, argv, i, arg);
                options.root = argv[i];
            } else if (arg == "--out") {
                require_value(argc, argv, i, arg);
                options.out = argv[i];
            } else if (arg == "--manifest") {
                require_value(argc, argv, i, arg);
                options.manifest = argv[i];
            } else if (arg == "--real") {
                require_value(argc, argv, i, arg);
                options.real = argv[i];
            } else if (arg == "--coded") {
                require_value(argc, argv, i, arg);
                options.coded = argv[i];
            } else if (arg == "--allow-blocked") {
                options.allow_blocked = true;
            } else if (arg == "--evidence") {
                options.evidence = true;
            } else if (arg == "--determinism") {
                options.determinism = true;
            } else if (arg == "--ci-run-id") {
                require_value(argc, argv, i, arg);
                options.ci_run_id = argv[i];
            } else if (arg == "--ci-run-url") {
                require_value(argc, argv, i, arg);
                options.ci_run_url = argv[i];
            } else if (arg == "--commit") {
                require_value(argc, argv, i, arg);
                options.commit = argv[i];
            } else if (arg == "--runner-os") {
                require_value(argc, argv, i, arg);
                options.runner_os = argv[i];
            } else if (arg == "--verify") {
                command = Command::Verify;
            } else if (arg == "--verify-evidence") {
                command = Command::VerifyEvidence;
            } else if (arg == "--stream") {
                require_value(argc, argv, i, arg);
                command = Command::Stream;
                id = argv[i];
            } else if (arg == "--sha256") {
                sha256 = true;
            } else if (arg == "--range") {
                command = Command::Range;
                if (i + 3 >= argc) throw std::invalid_argument("--range requires id offset len");
                id = argv[++i];
                offset = parse_bigint(argv[++i]);
                length = parse_bigint(argv[++i]);
            } else if (arg == "--materialize") {
                require_value(argc, argv, i, arg);
                command = Command::Materialize;
                id = argv[i];
            } else if (arg == "--to") {
                require_value(argc, argv, i, arg);
                to = argv[i];
            } else if (arg == "--list") {
                command = Command::List;
            } else if (arg == "--record-check") {
                command = Command::RecordCheck;
                for (int j = 0; j < 6; ++j) {
                    if (i + 1 >= argc) throw std::invalid_argument("--record-check requires six values");
                    record_args.emplace_back(argv[++i]);
                }
            } else if (arg == "--record-small") {
                require_value(argc, argv, i, arg);
                command = Command::RecordSmall;
                id = argv[i];
            } else if (arg == "--file") {
                require_value(argc, argv, i, arg);
                file = argv[i];
            } else if (arg == "--external-sha") {
                require_value(argc, argv, i, arg);
                external_sha = argv[i];
            } else {
                throw std::invalid_argument("unknown option: " + arg);
            }
        }

        options.root = fs::absolute(options.root);
        if (options.manifest.empty()) {
            options.manifest = options.root / "specs_and_reports" / "v2" / "fixtures.tsv";
        } else {
            options.manifest = fs::absolute(options.manifest);
        }
        if (!options.out.empty()) options.out = fs::absolute(options.out);
        if (!options.real.empty()) options.real = fs::absolute(options.real);
        if (!options.coded.empty()) options.coded = fs::absolute(options.coded);

        switch (command) {
            case Command::Generate:
                return generate(options);
            case Command::Verify:
                return verify(options);
            case Command::Stream:
                return stream_command(id, sha256, options);
            case Command::Range:
                return range_command(id, offset, length, options);
            case Command::Materialize: {
                if (to.empty()) throw std::invalid_argument("--materialize requires --to");
                const fs::path target = fs::absolute(to);
                const auto result = materialize(id, target, options);
                std::cout << result.fixture.id << "\t" << result.fixture.bytes.to_decimal()
                          << "\t" << digest_hex(result.fixture.sha256) << "\t"
                          << result.fixture.path << "\tallocated=" << result.allocated_bytes
                          << "\tsparse=" << (result.sparse ? "true" : "false") << "\n";
                if (options.evidence && id == "F02") {
                    record_sparse(context_from(options), result);
                }
                return 0;
            }
            case Command::List: {
                for (const auto& spec : catalogue(options)) {
                    std::cout << spec.id << '\t' << mode_name(spec.mode) << '\t'
                              << spec.bytes.to_decimal() << '\t' << spec.params << '\n';
                }
                return 0;
            }
            case Command::RecordCheck:
                if (record_args.size() != 6) throw std::invalid_argument("--record-check requires six values");
                record_check(context_from(options), record_args[0], record_args[1],
                             record_args[2], record_args[3], record_args[4], record_args[5]);
                return record_args[5] == "PASS" ? 0 : 1;
            case Command::RecordSmall:
                if (file.empty() || external_sha.empty()) {
                    throw std::invalid_argument("--record-small requires --file and --external-sha");
                }
                record_small(context_from(options), id, fs::absolute(file), external_sha);
                return 0;
            case Command::VerifyEvidence: {
                const int result = verify_evidence_sums(options.root);
                std::cout << (result == 0 ? "H1 evidence sums: PASS\n" : "H1 evidence sums: FAIL\n");
                return result;
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "mapr_fixtures: " << ex.what() << "\n";
        return 1;
    }
    return 1;
}
