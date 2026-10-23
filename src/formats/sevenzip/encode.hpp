#pragma once

#include "base/error.hpp"
#include "formats/sevenzip/folder.hpp"

#include <cstddef>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace bale::sevenzip {

// NOTE: 7z headers force a write-plan-then-emit shape: pack streams are
// compressed straight to the output file while the header (names, sizes,
// CRCs) accumulates in memory and is emitted at finish. The header stays
// bounded by Limits::maxHeaderBytes; pack data streams with a fixed buffer.
inline constexpr std::uint64_t lzma1DictBytes = std::uint64_t{1} << 20;
inline constexpr std::uint64_t lzma2DictBytes = std::uint64_t{8} << 20;

using PackedSink = std::function<Result<void>(std::span<const std::byte>)>;

class FolderEncoder {
  public:
    struct State;

    [[nodiscard]] static Result<FolderEncoder>
    create(Codec codec, int level, std::vector<std::byte>& props);

    FolderEncoder(FolderEncoder&& other) noexcept;
    FolderEncoder& operator=(FolderEncoder&& other) noexcept;
    ~FolderEncoder();

    [[nodiscard]] Result<void>
    supply(std::span<const std::byte> data, bool finish, const PackedSink& sink);

  private:
    explicit FolderEncoder(std::unique_ptr<State> state, Codec codec);

    std::unique_ptr<State> state_;
    Codec codec_;
};

}
