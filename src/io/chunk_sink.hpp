#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <span>
#include <type_traits>

namespace bale {

template <typename Sink>
concept ChunkSink = std::is_invocable_r_v<Result<void>, Sink&, std::span<const std::byte>>;

}
