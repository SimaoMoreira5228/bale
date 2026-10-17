#include "cli/terminal_text.hpp"

#include <doctest/doctest.h>

#include <string>
#include <string_view>

using namespace bale::cli;

TEST_CASE("escapeForTerminal returns clean names untouched without copying") {
    std::string buffer;
    std::string_view clean = "docs/caf\xC3\xA9/\xF0\x9F\x93\xA6.txt";

    auto shown = escapeForTerminal(clean, buffer);
    CHECK(shown == clean);
    CHECK(shown.data() == clean.data());
}

TEST_CASE("escapeForTerminal neutralizes terminal controls, bad UTF-8 and bidi overrides") {
    struct Case {
        std::string_view raw;
        std::string_view shown;
    };

    const Case cases[] = {
        {"a\x1b[31mb", "a\\x1b[31mb"},
        {"line\nbreak\r", "line\\x0abreak\\x0d"},
        {"del\x7f", "del\\x7f"},
        {"c1\xC2\x9B"
         "2J",
         "c1\\xc2\\x9b2J"},
        {"txt.\xE2\x80\xAE"
         "exe",
         "txt.\\xe2\\x80\\xaeexe"},
        {"iso\xE2\x81\xA6x", "iso\\xe2\\x81\\xa6x"},
        {"bad\xFFutf", "bad\\xffutf"},
        {"overlong\xC0\xAF", "overlong\\xc0\\xaf"},
        {"cut\xE2\x82", "cut\\xe2\\x82"},
        {"surrogate\xED\xA0\x80", "surrogate\\xed\\xa0\\x80"},
        {"back\\slash\x01", "back\\\\slash\\x01"},
    };

    std::string buffer;
    for (const Case& c : cases) {
        CAPTURE(c.shown);
        CHECK(escapeForTerminal(c.raw, buffer) == c.shown);
    }
}
