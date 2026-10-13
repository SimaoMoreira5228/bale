#include "archive/chunk_pipeline.hpp"

#include <algorithm>
#include <utility>

namespace bale::archive {

namespace {

// PERF: two chunks of ring space per worker keep every worker busy on large files, and sixteen
// slots per worker let small files queue behind a large chunk instead of stalling the writer; see
// bench/results/2026-10-18-xeon-e5-2690v3-threads.
constexpr std::size_t ringChunksPerWorker = 2;
constexpr std::size_t slotsPerWorker = 16;

}

std::optional<std::size_t> ByteRing::place(std::size_t size) const {
    if (live_ == 0) {
        return size <= bytes_.size() ? std::optional<std::size_t>(0) : std::nullopt;
    }
    if (wrapped_) {
        return tail_ - head_ >= size ? std::optional(head_) : std::nullopt;
    }
    if (bytes_.size() - head_ >= size) {
        return head_;
    }
    return size <= tail_ ? std::optional<std::size_t>(0) : std::nullopt;
}

std::span<std::byte> ByteRing::reserve(std::size_t size) {
    std::size_t offset = place(size).value_or(0);
    if (live_ == 0) {
        tail_ = 0;
        wrapped_ = false;
    } else if (offset == 0) {
        wrapped_ = true;
    }
    head_ = offset + size;
    ++live_;
    return bytes_.subspan(offset, size);
}

void ByteRing::shrink(std::span<std::byte> newest, std::size_t size) {
    head_ = static_cast<std::size_t>(newest.data() - bytes_.data()) + size;
}

void ByteRing::release(std::span<const std::byte> oldest) {
    auto offset = static_cast<std::size_t>(oldest.data() - bytes_.data());
    if (offset < tail_) {
        wrapped_ = false;
    }
    tail_ = offset + oldest.size();
    if (--live_ == 0) {
        head_ = 0;
        tail_ = 0;
        wrapped_ = false;
    }
}

ChunkPipeline::ChunkPipeline(
    std::vector<ChunkEncoder> encoders,
    std::uint32_t chunkSize,
    std::size_t slots,
    std::size_t ringChunks,
    bool encodes
) :
    chunkSize_(chunkSize), slots_(slots), stages_(slots, Stage::Free),
    encoders_(std::move(encoders)), inputs_(ringChunks * chunkSize),
    outputs_(encodes ? ringChunks * chunkSize : 0), encodes_(encodes) {
}

Result<std::unique_ptr<ChunkPipeline>> ChunkPipeline::create(
    const CompressionProfile& profile,
    std::uint32_t chunkSize,
    std::uint32_t workers
) {
    std::size_t encoderCount = workers == 1 ? 1 : std::size_t{workers} + 1;
    std::vector<ChunkEncoder> encoders;
    encoders.reserve(encoderCount);
    for (std::size_t encoder = 0; encoder < encoderCount; ++encoder) {
        auto created = ChunkEncoder::create(profile, chunkSize);
        if (!created) {
            return std::unexpected(created.error());
        }
        encoders.push_back(std::move(*created));
    }

    bool threaded = workers > 1;
    std::unique_ptr<ChunkPipeline> pipeline(new ChunkPipeline(
        std::move(encoders),
        chunkSize,
        threaded ? workers * slotsPerWorker : 1,
        threaded ? workers * ringChunksPerWorker : 1,
        profile.codec != CodecId::Raw
    ));
    if (threaded) {
        pipeline->workers_.reserve(workers);
        for (std::size_t worker = 0; worker < workers; ++worker) {
            pipeline->workers_.emplace_back([owner = pipeline.get(),
                                             worker](const std::stop_token& stop) {
                owner->work(stop, worker);
            });
        }
    }
    return pipeline;
}

ChunkPipeline::~ChunkPipeline() {
    cancel();
}

bool ChunkPipeline::full() const {
    return head_ - append_ == slots_.size() || (!reserved_ && !inputs_.fits(chunkSize_));
}

ChunkSlot& ChunkPipeline::freeSlot() {
    ChunkSlot& slot = slots_[indexOf(head_)];
    if (!reserved_) {
        slot.input = inputs_.reserve(chunkSize_);
        reserved_ = true;
    }
    return slot;
}

void ChunkPipeline::submit(std::size_t size) {
    std::size_t index = indexOf(head_);
    ChunkSlot& slot = slots_[index];
    inputs_.shrink(slot.input, size);
    slot.input = slot.input.first(size);
    slot.size = size;
    reserved_ = false;
    if (workers_.empty()) {
        run(index, Stage::Hashing, encoders_.back());
    }
    {
        std::scoped_lock lock(mutex_);
        stages_[index] = workers_.empty() ? Stage::Hashed : Stage::HashQueued;
        ++head_;
    }
    if (!workers_.empty()) {
        workReady_.notify_one();
    }
}

void ChunkPipeline::decided(bool encode) {
    std::size_t index = indexOf(decide_);
    ChunkSlot& slot = slots_[index];
    slot.codec = CodecId::Raw;
    slot.encodedSize = slot.size;
    slot.error.reset();
    slot.output = {};

    bool encodes = encode && outputBound(slot.size) != 0;
    if (encodes) {
        slot.output = outputs_.reserve(outputBound(slot.size));
        if (workers_.empty()) {
            run(index, Stage::Encoding, encoders_.back());
        }
    }
    bool queue = encodes && !workers_.empty();
    {
        std::scoped_lock lock(mutex_);
        stages_[index] = queue ? Stage::EncodeQueued : Stage::Ready;
        ++decide_;
    }
    if (queue) {
        workReady_.notify_one();
    }
}

void ChunkPipeline::release() {
    ChunkSlot& slot = slots_[indexOf(append_)];
    inputs_.release(slot.input);
    if (!slot.output.empty()) {
        outputs_.release(slot.output);
    }
    std::scoped_lock lock(mutex_);
    stages_[indexOf(append_)] = Stage::Free;
    ++append_;
}

std::optional<PipelineEvent> ChunkPipeline::next(bool wait) {
    std::unique_lock lock(mutex_);
    while (!cancelled_) {
        if (decidable()) {
            return PipelineEvent{
                .slot = &slots_[indexOf(decide_)],
                .step = PipelineStep::Decide,
            };
        }
        if (append_ < decide_ && stages_[indexOf(append_)] == Stage::Ready) {
            return PipelineEvent{
                .slot = &slots_[indexOf(append_)],
                .step = PipelineStep::Append,
            };
        }
        if (!wait || append_ == head_) {
            break;
        }

        auto blocking = claimBlocking();
        if (!blocking) {
            writerReady_.wait(lock);
            continue;
        }
        Stage stage = stages_[*blocking];
        lock.unlock();
        run(*blocking, stage, encoders_.back());
        lock.lock();
        stages_[*blocking] = stage == Stage::Hashing ? Stage::Hashed : Stage::Ready;
    }
    return std::nullopt;
}

void ChunkPipeline::cancel() {
    {
        std::scoped_lock lock(mutex_);
        cancelled_ = true;
    }
    workReady_.notify_all();
    writerReady_.notify_all();
}

std::size_t ChunkPipeline::outputBound(std::size_t size) const {
    return encodes_ ? size : 0;
}

bool ChunkPipeline::decidable() const {
    if (decide_ == head_ || stages_[indexOf(decide_)] != Stage::Hashed) {
        return false;
    }
    return outputs_.fits(outputBound(slots_[indexOf(decide_)].size));
}

std::optional<std::size_t> ChunkPipeline::claimBlocking() {
    std::size_t oldest = indexOf(append_);
    if (append_ < decide_ && stages_[oldest] == Stage::EncodeQueued) {
        stages_[oldest] = Stage::Encoding;
        return oldest;
    }
    std::size_t undecided = indexOf(decide_);
    if (decide_ < head_ && stages_[undecided] == Stage::HashQueued) {
        stages_[undecided] = Stage::Hashing;
        return undecided;
    }
    return std::nullopt;
}

std::optional<std::size_t> ChunkPipeline::claim() {
    for (std::uint64_t sequence = append_; sequence < head_; ++sequence) {
        std::size_t index = indexOf(sequence);
        if (stages_[index] == Stage::HashQueued) {
            stages_[index] = Stage::Hashing;
            return index;
        }
        if (stages_[index] == Stage::EncodeQueued) {
            stages_[index] = Stage::Encoding;
            return index;
        }
    }
    return std::nullopt;
}

void ChunkPipeline::work(const std::stop_token& stop, std::size_t worker) {
    ChunkEncoder& encoder = encoders_[worker];
    std::unique_lock lock(mutex_);
    while (true) {
        std::optional<std::size_t> index;
        workReady_.wait(lock, stop, [this, &index] {
            if (!cancelled_) {
                index = claim();
            }
            return cancelled_ || index.has_value();
        });
        if (!index) {
            return;
        }

        Stage stage = stages_[*index];
        lock.unlock();
        run(*index, stage, encoder);
        lock.lock();
        stages_[*index] = stage == Stage::Hashing ? Stage::Hashed : Stage::Ready;
        writerReady_.notify_one();
    }
}

void ChunkPipeline::run(std::size_t index, Stage stage, ChunkEncoder& encoder) {
    ChunkSlot& slot = slots_[index];
    if (stage == Stage::Hashing) {
        slot.key = chunkKeyOf(slot.chunk());
        return;
    }

    auto encoded = encoder.encode(slot.chunk());
    if (!encoded) {
        slot.error = encoded.error();
        return;
    }
    slot.codec = encoded->codec;
    slot.encodedSize = encoded->bytes.size();
    if (encoded->codec != CodecId::Raw) {
        std::ranges::copy(encoded->bytes, slot.output.begin());
    }
}

}
