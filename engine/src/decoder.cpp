#include "mapr/decoder.hpp"
#include "mapr/crypto.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <fstream>
#include <future>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace mapr {

namespace {

double read_peak_rss_mb() {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("VmHWM:", 0) == 0) {
            std::istringstream iss(line.substr(6));
            uint64_t kb = 0;
            iss >> kb;
            return static_cast<double>(kb) / 1024.0;
        }
    }
    return 0.0;
}

// Streaming BitSeq-to-MSB-bytes carry writer supporting arbitrary unaligned superchunk bit cuts
class RawByteCarryWriter {
public:
    explicit RawByteCarryWriter(std::ofstream& out, Sha256& sha)
        : out_(out), sha_(sha) {
        buf_.reserve(1u << 20);
    }

    void append_chunk(const BitSeq& seq) {
        uint64_t n = seq.bit_len();
        if (n == 0) return;
        size_t n_full = static_cast<size_t>(n >> 6);
        int rem = static_cast<int>(n & 63ULL);

        if (carry_bits_ == 0) {
            for (size_t i = 0; i < n_full; ++i) {
                emit_word64(seq.word(i));
            }
        } else {
            int rsh = 64 - carry_bits_;
            for (size_t i = 0; i < n_full; ++i) {
                uint64_t w = seq.word(i);
                uint64_t combined = carry_word_ | (w << carry_bits_);
                emit_word64(combined);
                carry_word_ = w >> rsh;
            }
        }

        if (rem > 0) {
            uint64_t tw = seq.word(n_full) & low_mask(rem);
            if (carry_bits_ == 0) {
                carry_word_ = tw;
                carry_bits_ = rem;
            } else {
                carry_word_ |= (tw << carry_bits_);
                if (carry_bits_ + rem >= 64) {
                    emit_word64(carry_word_);
                    int consumed = 64 - carry_bits_;
                    carry_word_ = (consumed == 64) ? 0ULL : (tw >> consumed);
                    carry_bits_ = (carry_bits_ + rem) - 64;
                } else {
                    carry_bits_ += rem;
                }
            }
        }
    }

    uint64_t finish() {
        if ((carry_bits_ & 7) != 0) {
            throw std::runtime_error("Total decoded bits not divisible by 8 in raw-byte mode");
        }
        int rem_bytes = carry_bits_ >> 3;
        if (rem_bytes > 0) {
            uint64_t rev = bitrev_bytes64(carry_word_);
            for (int b = 0; b < rem_bytes; ++b) {
                buf_.push_back(static_cast<uint8_t>((rev >> (8 * b)) & 0xFFu));
            }
            carry_bits_ = 0;
            carry_word_ = 0ULL;
        }
        flush_buf();
        return total_bytes_;
    }

private:
    void emit_word64(uint64_t w) {
        size_t pos = buf_.size();
        buf_.resize(pos + 8);
        write_le64(buf_.data() + pos, bitrev_bytes64(w));
        if (buf_.size() >= (1u << 20)) {
            flush_buf();
        }
    }

    void flush_buf() {
        if (buf_.empty()) return;
        sha_.update(buf_.data(), buf_.size());
        out_.write(reinterpret_cast<const char*>(buf_.data()), static_cast<std::streamsize>(buf_.size()));
        if (!out_) throw std::runtime_error("Failed writing reconstructed output file");
        total_bytes_ += buf_.size();
        buf_.clear();
    }

    std::ofstream& out_;
    Sha256& sha_;
    std::vector<uint8_t> buf_;
    uint64_t carry_word_ = 0ULL;
    int carry_bits_ = 0;
    uint64_t total_bytes_ = 0ULL;
};

// Bounded-RAM batch chunk evaluator shared by streaming & BitSeq decoders
template <typename ChunkConsumer>
void stream_decode_chunks(ContainerReader& reader, unsigned num_threads, ChunkConsumer&& on_chunk) {
    const auto& meta = reader.meta();
    uint64_t K = meta.chunk_count;
    unsigned T = std::max(1u, num_threads);
    size_t batch_sz = std::max<size_t>(4, 2 * T);

    std::unordered_map<uint64_t, BitSeq> hist_map;
    uint32_t w_hist = meta.config.w_hist;

    for (uint64_t base = 0; base < K; base += batch_sz) {
        size_t cnt = static_cast<size_t>(std::min<uint64_t>(batch_sz, K - base));
        std::vector<ContainerReader::ChunkFrame> frames(cnt);
        for (size_t i = 0; i < cnt; ++i) {
            frames[i] = reader.read_chunk(base + i);
        }

        // Evaluate all explicit DAG chunks in parallel across worker threads
        std::vector<BitSeq> explicit_seqs(cnt);
        std::vector<size_t> exp_idx;
        for (size_t i = 0; i < cnt; ++i) {
            if (frames[i].chunk_kind == KIND_EXPLICIT_DAG) exp_idx.push_back(i);
        }

        if (T <= 1 || exp_idx.size() <= 1) {
            for (size_t i : exp_idx) {
                explicit_seqs[i] = evaluate_chunk_dag(frames[i].dag, frames[i].bit_len);
                frames[i].dag = ExplicitChunkDAG{};
            }
        } else {
            size_t nw = std::min<size_t>(T, exp_idx.size());
            std::atomic<size_t> next_w{0};
            std::vector<std::future<void>> futs;
            futs.reserve(nw);
            for (size_t w = 0; w < nw; ++w) {
                futs.push_back(std::async(std::launch::async, [&]() {
                    while (true) {
                        size_t k = next_w.fetch_add(1);
                        if (k >= exp_idx.size()) break;
                        size_t i = exp_idx[k];
                        explicit_seqs[i] = evaluate_chunk_dag(frames[i].dag, frames[i].bit_len);
                        frames[i].dag = ExplicitChunkDAG{};
                    }
                }));
            }
            for (auto& f : futs) f.get();
        }

        // Resolve CHUNK_REFs and emit in exact sequential order while evicting expired window entries
        for (size_t i = 0; i < cnt; ++i) {
            uint64_t c = base + i;
            BitSeq cur;
            if (frames[i].chunk_kind == KIND_CHUNK_REF) {
                auto it = hist_map.find(frames[i].ref_target);
                if (it == hist_map.end()) {
                    throw std::runtime_error("CHUNK_REF target missing from W_hist window");
                }
                cur = it->second.apply_v4(frames[i].v4_op);
            } else {
                cur = std::move(explicit_seqs[i]);
            }

            on_chunk(cur);

            if (w_hist > 0) {
                hist_map[c] = std::move(cur);
                if (c >= w_hist) {
                    hist_map.erase(c - w_hist);
                }
            }
        }
    }
}

} // namespace

std::pair<BitSeq, DecodeStats> decode_mapr_to_bitseq(
    const std::string& in_mapr_path, unsigned num_threads) {
    auto t0 = std::chrono::steady_clock::now();
    ContainerReader reader(in_mapr_path);
    const auto& meta = reader.meta();

    BitSeqAppender app(meta.total_bits);
    stream_decode_chunks(reader, num_threads, [&](const BitSeq& ch) {
        app.append_seq(ch);
    });
    BitSeq out = app.finish();
    if (out.bit_len() != meta.total_bits) {
        throw std::runtime_error("Total reconstructed bit length mismatch");
    }

    std::array<uint8_t, 32> actual_sha{};
    if ((meta.flags & FLAG_RAW_BYTES_MSB) != 0u) {
        auto bytes = out.to_bytes_msb();
        actual_sha = Sha256::hash(bytes.data(), bytes.size());
    } else {
        actual_sha = out.canonical_sha256();
    }
    if (actual_sha != meta.stream_sha256) {
        throw std::runtime_error("End-to-end SHA-256 verification failed!");
    }

    auto t1 = std::chrono::steady_clock::now();
    DecodeStats st;
    st.output_bits = out.bit_len();
    st.output_bytes = (out.bit_len() + 7ULL) >> 3;
    st.chunk_count = meta.chunk_count;
    st.wall_seconds = std::chrono::duration<double>(t1 - t0).count();
    st.peak_rss_mb = read_peak_rss_mb();
    st.stream_sha256_hex = Sha256::to_hex(actual_sha);
    st.sha256_verified = true;
    return {std::move(out), st};
}

DecodeStats decode_mapr_to_raw_file(
    const std::string& in_mapr_path,
    const std::string& out_raw_path,
    unsigned num_threads) {
    auto t0 = std::chrono::steady_clock::now();
    ContainerReader reader(in_mapr_path);
    const auto& meta = reader.meta();
    if ((meta.total_bits & 7ULL) != 0ULL) {
        throw std::runtime_error("Cannot decode non-byte-aligned sequence in --raw-bytes mode");
    }

    std::ofstream out(out_raw_path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Cannot open output file: " + out_raw_path);

    Sha256 sha_raw;
    RawByteCarryWriter writer(out, sha_raw);
    uint64_t acc_bits = 0ULL;

    stream_decode_chunks(reader, num_threads, [&](const BitSeq& ch) {
        acc_bits += ch.bit_len();
        writer.append_chunk(ch);
    });
    uint64_t written_bytes = writer.finish();
    out.flush();
    out.close();

    if (acc_bits != meta.total_bits || written_bytes * 8ULL != meta.total_bits) {
        throw std::runtime_error("Reconstructed byte/bit count mismatch");
    }

    std::array<uint8_t, 32> actual_sha{};
    if ((meta.flags & FLAG_RAW_BYTES_MSB) != 0u) {
        actual_sha = sha_raw.finalize();
    } else {
        // Container was encoded in bitseq mode (canonical_sha256 includes 8B bit_len prefix)
        std::ifstream verify_in(out_raw_path, std::ios::binary);
        Sha256 csha;
        uint8_t len_be[8];
        write_be64(len_be, meta.total_bits);
        csha.update(len_be, 8);
        std::vector<uint8_t> tmp(1u << 16);
        while (verify_in) {
            verify_in.read(reinterpret_cast<char*>(tmp.data()), static_cast<std::streamsize>(tmp.size()));
            auto g = verify_in.gcount();
            if (g > 0) csha.update(tmp.data(), static_cast<size_t>(g));
        }
        actual_sha = csha.finalize();
    }

    if (actual_sha != meta.stream_sha256) {
        throw std::runtime_error("Reconstructed file SHA-256 mismatch against .mapr trailer!");
    }

    auto t1 = std::chrono::steady_clock::now();
    DecodeStats st;
    st.output_bits = meta.total_bits;
    st.output_bytes = written_bytes;
    st.chunk_count = meta.chunk_count;
    st.wall_seconds = std::chrono::duration<double>(t1 - t0).count();
    st.peak_rss_mb = read_peak_rss_mb();
    st.stream_sha256_hex = Sha256::to_hex(actual_sha);
    st.sha256_verified = true;
    return st;
}

FullInspectReport inspect_mapr_container(const std::string& in_mapr_path) {
    ContainerReader reader(in_mapr_path);
    FullInspectReport rep;
    rep.meta = reader.meta();
    rep.file_size = reader.file_size();

    for (uint64_t c = 0; c < rep.meta.chunk_count; ++c) {
        auto cf = reader.read_chunk(c);
        if (cf.chunk_kind == KIND_CHUNK_REF) {
            rep.summary.add_chunk_ref(cf.bit_len, cf.v4_op);
        } else {
            rep.summary.add_chunk_dag(cf.dag, cf.bit_len);
        }
    }
    if (rep.summary.accounted_bits != rep.meta.total_bits) {
        throw std::runtime_error("Bit accountability invariant violation!");
    }
    return rep;
}

} // namespace mapr
