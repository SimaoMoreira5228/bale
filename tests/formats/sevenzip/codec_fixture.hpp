#pragma once

#include "formats/sevenzip/fixture_bytes.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include <lzma.h>

namespace bale::sevenzip::test {

inline Bytes lzma1Encode(std::span<const std::byte> data) {
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_options_lzma options;
    if (lzma_lzma_preset(&options, 1) != LZMA_OK) {
        return {};
    }
    options.dict_size = 1U << 12;
    options.lc = 3;
    options.lp = 0;
    options.pb = 2;
    lzma_filter filters[2] = {
        {.id = LZMA_FILTER_LZMA1, .options = &options},
        {.id = LZMA_VLI_UNKNOWN, .options = nullptr},
    };
    if (lzma_raw_encoder(&stream, filters) != LZMA_OK) {
        return {};
    }

    Bytes out(data.size() + 64);
    stream.next_in = reinterpret_cast<const std::uint8_t*>(data.data());
    stream.avail_in = data.size();
    while (true) {
        if (stream.total_out == out.size()) {
            out.resize(out.size() + data.size() + 64);
        }
        stream.next_out = reinterpret_cast<std::uint8_t*>(out.data() + stream.total_out);
        stream.avail_out = out.size() - static_cast<std::size_t>(stream.total_out);
        auto status = lzma_code(&stream, LZMA_FINISH);
        if (status == LZMA_STREAM_END) {
            break;
        }
        if (status != LZMA_OK) {
            lzma_end(&stream);
            return {};
        }
    }

    out.resize(static_cast<std::size_t>(stream.total_out));
    lzma_end(&stream);
    return out;
}

inline Bytes lzma2Encode(std::span<const std::byte> data) {
    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_options_lzma options;
    if (lzma_lzma_preset(&options, 1) != LZMA_OK) {
        return {};
    }
    options.dict_size = 1U << 12;
    lzma_filter filters[2] = {
        {.id = LZMA_FILTER_LZMA2, .options = &options},
        {.id = LZMA_VLI_UNKNOWN, .options = nullptr},
    };
    if (lzma_raw_encoder(&stream, filters) != LZMA_OK) {
        return {};
    }

    Bytes out(data.size() + 64);
    stream.next_in = reinterpret_cast<const std::uint8_t*>(data.data());
    stream.avail_in = data.size();
    while (true) {
        if (stream.total_out == out.size()) {
            out.resize(out.size() + data.size() + 64);
        }
        stream.next_out = reinterpret_cast<std::uint8_t*>(out.data() + stream.total_out);
        stream.avail_out = out.size() - static_cast<std::size_t>(stream.total_out);
        auto status = lzma_code(&stream, LZMA_FINISH);
        if (status == LZMA_STREAM_END) {
            break;
        }
        if (status != LZMA_OK) {
            lzma_end(&stream);
            return {};
        }
    }

    out.resize(static_cast<std::size_t>(stream.total_out));
    lzma_end(&stream);
    return out;
}

inline Bytes lzma2BcjEncode(std::span<const std::byte> data) {
    lzma_options_lzma lzmaOptions;
    if (lzma_lzma_preset(&lzmaOptions, 1) != LZMA_OK) {
        return {};
    }
    lzmaOptions.dict_size = 1U << 12;
    lzma_options_bcj bcjOptions{.start_offset = 0};
    lzma_filter filters[3] = {
        {.id = LZMA_FILTER_X86, .options = &bcjOptions},
        {.id = LZMA_FILTER_LZMA2, .options = &lzmaOptions},
        {.id = LZMA_VLI_UNKNOWN, .options = nullptr},
    };
    Bytes out(data.size() + 64);
    std::size_t position = 0;
    auto status = lzma_raw_buffer_encode(
        filters,
        nullptr,
        reinterpret_cast<const std::uint8_t*>(data.data()),
        data.size(),
        reinterpret_cast<std::uint8_t*>(out.data()),
        &position,
        out.size()
    );
    if (status != LZMA_OK) {
        return {};
    }
    out.resize(position);
    return out;
}

inline Bytes aesProps() {
    Bytes props;
    for (std::uint8_t index = 0; index < 18; ++index) {
        props.push_back(static_cast<std::byte>(0xA0 + index));
    }
    return props;
}

}
