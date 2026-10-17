#include "checksum/blake3.hpp"

#include <doctest/doctest.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

using namespace bale;

namespace {

struct Vector {
    HashDomain domain;
    std::size_t length;
    std::string_view digest;
};

// NOTE: expected digests come from the official Rust b3sum 1.8.5 (`b3sum --derive-key <context>`)
// over the BLAKE3 test-vector input pattern, an implementation independent of the C library.
constexpr Vector vectors[] = {
    {HashDomain::Chunk, 0, "0bb417b0282a711c1ad7d7d0bea762acaec93cd67be228c526335d5ed2fda619"},
    {HashDomain::Chunk, 1, "d585d26203df0cb1d9d9e8c65c9091aa662845e5535d0bd946567dd14c40e7c2"},
    {HashDomain::Chunk, 1024, "3d48ab5e72bc978a1e83cae3aadea5ce2232f01adea7310be5edc202997d68b8"},
    {HashDomain::Chunk, 1025, "29482359135c9fe4be1a9926c4940f94fdf05d36473102ec6258835589ee697e"},
    {HashDomain::Chunk, 102400, "3dc6fc795b8ee9019d8278063458471fc229f141936267d6c1f039446ecfbafd"},
    {HashDomain::Chunk,
     1048577,
     "a699a92023c8799c58a5e0c6cb5f0ebdeae95804cc301cc9d2857f16e6a708d4"},
    {HashDomain::Manifest, 0, "f456c3145067ce77ccc42173ab07a45a0f80c1ff120764b89f96422e65db5c07"},
    {HashDomain::Manifest,
     1025,
     "063d6a2a62a7eebfcc500edfd54882302ef55c8727ad4a7620eb6f14a1dca921"},
    {HashDomain::Manifest,
     1048577,
     "47e7cfc54cf1000d07eb7f2f6ce12f37dd110fb63addbd8644d035316ed33833"},
    {HashDomain::Index, 0, "6a2dbe21fba906c4d8475a1dba849ea29fa5da1fd53874a8a33a64dc66b55287"},
    {HashDomain::Index, 1025, "0d7701fc2e4f0717bf4cb0f3ea093f416ee7187a647b28877919854eaef0a888"},
    {HashDomain::Index,
     1048577,
     "1a4d9a619ed309c0e9862c6df4bbfd6a3f41e58074a64537d1ebe1eef65023d0"},
    {HashDomain::Commit, 0, "361c16a71b90d6d5ace6703cbb1e7f56e1423ad2c151c9d10d45da4b3570673c"},
    {HashDomain::Commit, 1025, "50492f2c00d1fdea94be6f0f02c5ad3e66c89b68960b2eb19d0a9e6d1f80bc36"},
    {HashDomain::Commit,
     1048577,
     "d271b8747deb7da27db8c895755b3c95484ebd7cee11f16717043af21c4a8cd1"},
};

std::vector<std::byte> pattern(std::size_t length) {
    std::vector<std::byte> out(length);
    for (std::size_t index = 0; index < length; ++index) {
        out[index] = static_cast<std::byte>(index % 251);
    }
    return out;
}

std::string hex(const Blake3Digest& digest) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string out;
    for (std::byte value : digest) {
        auto byte = std::to_integer<unsigned>(value);
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0xF]);
    }
    return out;
}

}

TEST_CASE("domain-separated BLAKE3 digests match the reference b3sum") {
    for (const auto& vector : vectors) {
        CAPTURE(hashContext(vector.domain));
        CAPTURE(vector.length);
        auto input = pattern(vector.length);
        CHECK(hex(Blake3::of(vector.domain, input)) == vector.digest);
    }
}

TEST_CASE("incremental BLAKE3 updates at awkward boundaries and reset match one-shot digests") {
    auto input = pattern(1048577);
    auto expected = Blake3::of(HashDomain::Chunk, input);

    Blake3 hasher(HashDomain::Chunk);
    std::size_t position = 0;
    std::size_t step = 1;
    while (position < input.size()) {
        auto take = std::min(step, input.size() - position);
        hasher.update(std::span(input).subspan(position, take));
        position += take;
        step = step * 3 + 7;
    }
    CHECK(hasher.digest() == expected);

    hasher.reset();
    hasher.update(std::span(input).first(1025));
    CHECK(hex(hasher.digest()) == vectors[3].digest);

    Blake3 copy = hasher;
    copy.update(std::span(input).subspan(1025, 1));
    CHECK(hasher.digest() == Blake3::of(HashDomain::Chunk, std::span(input).first(1025)));
    CHECK(copy.digest() == Blake3::of(HashDomain::Chunk, std::span(input).first(1026)));
}
