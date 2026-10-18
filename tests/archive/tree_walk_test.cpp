#ifdef _WIN32

#include "archive/reader.hpp"
#include "archive/writer.hpp"

#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <utility>

using namespace bale;
using namespace bale::archive;

namespace fs = std::filesystem;

TEST_CASE("a Windows name that is not valid UTF-16 is skipped with a reason") {
    bale::test::TempPath temp;
    const fs::path root = temp.path() / "tree";
    fs::create_directories(root / "dir");
    std::ofstream(root / "dir" / L"bad\xD800name", std::ios::binary) << "x";
    std::ofstream(root / "dir" / L"café", std::ios::binary) << "y";
    if (!fs::exists(root / "dir" / L"bad\xD800name")) {
        MESSAGE("the filesystem cannot store unpaired surrogates");
        return;
    }

    const fs::path archivePath = temp.path() / "out.bale";
    auto file = File::createNew(archivePath);
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file));
    REQUIRE(writer);
    REQUIRE(writer->addTree(root, archivePath));
    REQUIRE(writer->skipped().size() == 1);
    CHECK(writer->skipped()[0].path == "dir/bad\xEF\xBF\xBDname");
    CHECK(writer->skipped()[0].reason == "name is not valid UTF-16");
    REQUIRE(writer->finish());

    auto archived = File::openRead(archivePath);
    REQUIRE(archived);
    auto reader = Reader::open(std::move(*archived));
    REQUIRE(reader);
    REQUIRE(reader->manifest().entries.size() == 2);
    CHECK(reader->manifest().entries[1].path == "dir/caf\xC3\xA9");
}

#endif
