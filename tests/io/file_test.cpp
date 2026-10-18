#include "io/file.hpp"

#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <filesystem>
#include <system_error>

using namespace bale;

using bale::test::TempPath;

TEST_CASE("File appends, reports size and reads at offsets") {
    TempPath temp;
    auto file = File::createNew(temp.path());
    REQUIRE(file);

    std::array<std::byte, 4> first{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    std::array<std::byte, 2> second{std::byte{5}, std::byte{6}};
    REQUIRE(file->append(first));
    REQUIRE(file->append(second));
    REQUIRE(file->sync());
    CHECK(file->size() == 6);

    auto reopened = File::openRead(temp.path());
    REQUIRE(reopened);

    std::array<std::byte, 3> middle{};
    REQUIRE(reopened->readExactAt(2, middle));
    CHECK(middle == std::array{std::byte{3}, std::byte{4}, std::byte{5}});

    std::array<std::byte, 8> tooMuch{};
    CHECK(reopened->readAt(4, tooMuch) == 2);
    CHECK(reopened->readAt(6, tooMuch) == 0);

    auto truncated = reopened->readExactAt(4, tooMuch);
    REQUIRE_FALSE(truncated);
    CHECK(truncated.error().kind == ErrorKind::Truncated);
}

TEST_CASE("File::writeAt patches in place while append and truncate keep writing at the end") {
    TempPath temp;
    std::array<std::byte, 2> patch{std::byte{7}, std::byte{8}};
    {
        auto file = File::createNew(temp.path());
        REQUIRE(file);

        std::array<std::byte, 4> zeros{};
        std::array<std::byte, 1> tail{std::byte{9}};
        REQUIRE(file->append(zeros));
        REQUIRE(file->writeAt(1, patch));
        REQUIRE(file->append(tail));
        REQUIRE(file->truncate(3));
        REQUIRE(file->append(tail));

        std::array<std::byte, 4> contents{};
        REQUIRE(file->readExactAt(0, contents));
        CHECK(contents == std::array{std::byte{0}, std::byte{7}, std::byte{8}, std::byte{9}});
        CHECK(file->size() == 4);
    }

    auto appendOnly = File::openAppend(temp.path());
    REQUIRE(appendOnly);
    CHECK_FALSE(appendOnly->writeAt(0, patch));
}

TEST_CASE("File::createNew refuses an existing path") {
    TempPath temp;
    REQUIRE(File::createNew(temp.path()));

    auto again = File::createNew(temp.path());
    REQUIRE_FALSE(again);
    CHECK(again.error().kind == ErrorKind::AlreadyExists);
    CHECK(again.error().systemCode != 0);
}

TEST_CASE("File::openRegularNoFollow opens regular files and refuses directories and symlinks") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());
    auto regular = temp.path() / "regular";
    REQUIRE(File::createNew(regular));

    CHECK(File::openRegularNoFollow(regular));

    auto directory = File::openRegularNoFollow(temp.path());
    REQUIRE_FALSE(directory);

    std::error_code error;
    std::filesystem::create_symlink(regular, temp.path() / "link", error);
    if (!error) {
        auto link = File::openRegularNoFollow(temp.path() / "link");
        REQUIRE_FALSE(link);
        CHECK(File::openRead(temp.path() / "link"));
    }
}
