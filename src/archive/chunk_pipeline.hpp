#pragma once

#include "archive/chunk.hpp"
#include "archive/chunk_codec.hpp"
#include "archive/writer_profile.hpp"
#include "base/error.hpp"
#include "format/record.hpp"

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <thread>
#include <vector>

namespace bale::archive {

struct ChunkSlot {
    std::span<std::byte> input;
    std::span<std::byte> output;
    std::size_t size = 0;
    ChunkKey key;
    CodecId codec = CodecId::Raw;
    std::size_t encodedSize = 0;
    std::optional<Error> error;
    std::size_t reference = 0;
    std::optional<std::uint32_t> indexPosition;

    [[nodiscard]] std::span<const std::byte> chunk() const {
        return input.first(size);
    }

    [[nodiscard]] std::span<const std::byte> stored() const {
        if (codec == CodecId::Raw) {
            return chunk();
        }
        return output.first(encodedSize);
    }
};

class ByteRing {
  public:
    explicit ByteRing(std::size_t capacity) :
        storage_(std::make_unique_for_overwrite<std::byte[]>(capacity)),
        bytes_(storage_.get(), capacity) {
    }

    [[nodiscard]] bool fits(std::size_t size) const {
        return place(size).has_value();
    }

    [[nodiscard]] std::span<std::byte> reserve(std::size_t size);
    void shrink(std::span<std::byte> newest, std::size_t size);
    void release(std::span<const std::byte> oldest);

  private:
    [[nodiscard]] std::optional<std::size_t> place(std::size_t size) const;

    std::unique_ptr<std::byte[]> storage_;
    std::span<std::byte> bytes_;
    std::size_t head_ = 0;
    std::size_t tail_ = 0;
    std::size_t live_ = 0;
    bool wrapped_ = false;
};

enum class PipelineStep : std::uint8_t {
    Decide,
    Append,
};

struct PipelineEvent {
    ChunkSlot* slot = nullptr;
    PipelineStep step = PipelineStep::Decide;
};

class ChunkPipeline {
  public:
    [[nodiscard]] static Result<std::unique_ptr<ChunkPipeline>>
    create(const CompressionProfile& profile, std::uint32_t chunkSize, std::uint32_t workers);

    ChunkPipeline(const ChunkPipeline&) = delete;
    ChunkPipeline& operator=(const ChunkPipeline&) = delete;
    ~ChunkPipeline();

    [[nodiscard]] bool full() const;
    [[nodiscard]] ChunkSlot& freeSlot();
    void submit(std::size_t size);
    void decided(bool encode);
    void release();

    [[nodiscard]] std::optional<PipelineEvent> next(bool wait);
    void cancel();

  private:
    enum class Stage : std::uint8_t {
        Free,
        HashQueued,
        Hashing,
        Hashed,
        EncodeQueued,
        Encoding,
        Ready,
    };

    ChunkPipeline(
        std::vector<ChunkEncoder> encoders,
        std::uint32_t chunkSize,
        std::size_t slots,
        std::size_t ringChunks,
        bool encodes
    );

    [[nodiscard]] std::size_t indexOf(std::uint64_t sequence) const {
        return static_cast<std::size_t>(sequence % slots_.size());
    }

    [[nodiscard]] std::size_t outputBound(std::size_t size) const;
    [[nodiscard]] bool decidable() const;
    [[nodiscard]] std::optional<std::size_t> claim();
    [[nodiscard]] std::optional<std::size_t> claimBlocking();
    void work(std::size_t worker);
    void run(std::size_t index, Stage stage, ChunkEncoder& encoder);

    std::mutex mutex_;
    std::condition_variable_any workReady_;
    std::condition_variable writerReady_;
    std::uint32_t chunkSize_;
    std::vector<ChunkSlot> slots_;
    std::vector<Stage> stages_;
    std::vector<ChunkEncoder> encoders_;
    ByteRing inputs_;
    ByteRing outputs_;
    bool encodes_ = false;
    bool reserved_ = false;
    bool cancelled_ = false;
    std::uint64_t head_ = 0;
    std::uint64_t decide_ = 0;
    std::uint64_t append_ = 0;
    std::vector<std::thread> workers_;
};

}
