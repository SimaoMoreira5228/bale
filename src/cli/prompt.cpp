#include "cli/prompt.hpp"

#include <sodium/utils.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <ranges>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace bale::cli {

namespace {

#ifndef _WIN32
Result<crypto::SecretBytes> readPosixPassword(std::string_view prompt) {
    std::FILE* tty = std::fopen("/dev/tty", "r+");
    if (tty == nullptr) {
        return fail(
            ErrorKind::PasswordRequired,
            "encrypted archive needs a password from a terminal"
        );
    }
    int fd = fileno(tty);
    termios original{};
    if (tcgetattr(fd, &original) != 0) {
        std::fclose(tty);
        return fail(ErrorKind::Io, "cannot query terminal attributes");
    }
    termios noEcho = original;
    noEcho.c_lflag &= static_cast<unsigned>(~ECHO);
    if (tcsetattr(fd, TCSAFLUSH, &noEcho) != 0) {
        std::fclose(tty);
        return fail(ErrorKind::Io, "cannot disable terminal echo");
    }
    std::fwrite(prompt.data(), 1, prompt.size(), tty);
    std::fflush(tty);

    std::string line;
    line.reserve(128);
    bool ok = false;
    while (true) {
        // NOLINTNEXTLINE(clang-analyzer-unix.Stream)
        int ch = std::fgetc(tty);
        if (ch == EOF || ch == '\n' || ch == '\r') {
            ok = true;
            break;
        }
        if (line.size() >= 4096) {
            break;
        }
        line.push_back(static_cast<char>(ch));
    }
    tcsetattr(fd, TCSAFLUSH, &original);
    // NOLINTNEXTLINE(clang-analyzer-unix.Stream)
    std::fputc('\n', tty);
    std::fclose(tty);
    if (!ok) {
        sodium_memzero(line.data(), line.size());
        return fail(ErrorKind::PasswordRequired, "cannot read password");
    }

    auto made = crypto::SecretBytes::make(line.size());
    if (!made) {
        sodium_memzero(line.data(), line.size());
        return std::unexpected(made.error());
    }
    crypto::SecretBytes out(std::move(*made));
    std::ranges::copy(std::as_bytes(std::span(line)), out.mut().begin());
    sodium_memzero(line.data(), line.size());
    return out;
}

#endif

#ifdef _WIN32
Result<crypto::SecretBytes> readWindowsPassword(std::string_view prompt) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE output = GetStdHandle(STD_ERROR_HANDLE);
    if (input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE) {
        return fail(
            ErrorKind::PasswordRequired,
            "encrypted archive needs a password from a terminal"
        );
    }
    DWORD mode = 0;
    if (GetConsoleMode(input, &mode) == 0) {
        return fail(
            ErrorKind::PasswordRequired,
            "encrypted archive needs a password from a terminal"
        );
    }
    DWORD noEcho = mode & static_cast<DWORD>(~ENABLE_ECHO_INPUT);
    if (SetConsoleMode(input, noEcho) == 0) {
        return fail(ErrorKind::Io, "cannot disable console echo");
    }
    std::string narrow(prompt);
    DWORD written = 0;
    WriteConsoleA(output, narrow.c_str(), static_cast<DWORD>(narrow.size()), &written, nullptr);

    std::wstring wide;
    wide.reserve(128);
    wchar_t buffer[128]{};
    bool ok = false;
    while (true) {
        DWORD got = 0;
        if (ReadConsoleW(input, buffer, 127, &got, nullptr) == 0) {
            break;
        }
        for (DWORD index = 0; index < got; ++index) {
            if (buffer[index] == L'\r' || buffer[index] == L'\n') {
                ok = true;
                break;
            }
            if (wide.size() < 4096) {
                wide.push_back(buffer[index]);
            }
        }
        if (ok) {
            break;
        }
    }
    SetConsoleMode(input, mode);
    DWORD ignored = 0;
    WriteConsoleA(output, "\r\n", 2, &ignored, nullptr);
    if (!ok) {
        SecureZeroMemory(wide.data(), wide.size() * sizeof(wchar_t));
        return fail(ErrorKind::PasswordRequired, "cannot read password");
    }
    int bytes = WideCharToMultiByte(
        CP_UTF8,
        0,
        wide.data(),
        static_cast<int>(wide.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (bytes <= 0) {
        SecureZeroMemory(wide.data(), wide.size() * sizeof(wchar_t));
        return fail(ErrorKind::Io, "cannot encode password");
    }
    std::string utf8(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        wide.data(),
        static_cast<int>(wide.size()),
        utf8.data(),
        bytes,
        nullptr,
        nullptr
    );
    SecureZeroMemory(wide.data(), wide.size() * sizeof(wchar_t));

    auto made = crypto::SecretBytes::make(utf8.size());
    if (!made) {
        sodium_memzero(utf8.data(), utf8.size());
        return std::unexpected(made.error());
    }
    crypto::SecretBytes out(std::move(*made));
    std::ranges::copy(std::as_bytes(std::span(utf8)), out.mut().begin());
    sodium_memzero(utf8.data(), utf8.size());
    return out;
}
#endif

}

Result<crypto::SecretBytes> promptPassword(std::string_view prompt) {
#ifdef _WIN32
    return readWindowsPassword(prompt);
#else
    return readPosixPassword(prompt);
#endif
}

}
