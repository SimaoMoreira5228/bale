#pragma once

#include "archive/writer.hpp"
#include "base/error.hpp"
#include "formats/tar/writer.hpp"
#include "formats/zip/writer.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace bale::cli {

enum class OutputFormat : std::uint8_t {
    Bale,
    Zip,
    Tar,
    TarGzip,
    TarZstd,
};

[[nodiscard]] std::optional<OutputFormat> parseOutputFormat(std::string_view text);

[[nodiscard]] std::optional<OutputFormat> outputFormatFromName(std::string_view path);

[[nodiscard]] std::string_view name(OutputFormat format);

[[nodiscard]] std::optional<std::string_view> checkOutputLevel(OutputFormat format, int level);

struct OutputOptions {
    OutputFormat format = OutputFormat::Bale;
    std::optional<int> level{};
    archive::WriterOptions native;
};

struct OutputSummary {
    std::uint64_t entries = 0;
    std::uint64_t archiveSize = 0;
    std::optional<archive::WriteSummary> native{};
};

class ArchiveOutput {
  public:
    [[nodiscard]] static Result<ArchiveOutput> create(File file, const OutputOptions& options);

    [[nodiscard]] OutputFormat format() const {
        return format_;
    }

    [[nodiscard]] bool storesHardLinks() const {
        return format_ != OutputFormat::Zip;
    }

    [[nodiscard]] Result<void>
    addDirectory(std::string_view path, const archive::EntryAttributes& attributes);

    [[nodiscard]] Result<void> addSymlink(
        std::string_view path,
        std::string_view target,
        const archive::EntryAttributes& attributes
    );

    [[nodiscard]] Result<void> addHardLink(
        std::string_view path,
        std::string_view target,
        const archive::EntryAttributes& attributes
    );

    [[nodiscard]] Result<void> beginFile(
        std::string_view path,
        std::uint64_t size,
        const archive::EntryAttributes& attributes
    );

    [[nodiscard]] Result<void> writeFile(std::span<const std::byte> data);

    [[nodiscard]] Result<void> endFile();

    [[nodiscard]] Result<void> addFile(
        std::string_view path,
        const File& source,
        std::uint64_t size,
        const archive::EntryAttributes& attributes
    );

    [[nodiscard]] Result<OutputSummary> finish();

  private:
    using Sink = std::variant<archive::Writer, tar::Writer, zip::Writer>;

    ArchiveOutput(Sink sink, OutputFormat format, bool durable) :
        sink_(std::move(sink)), format_(format), durable_(durable) {
    }

    Sink sink_;
    OutputFormat format_;
    bool durable_ = false;
    std::vector<std::byte> scratch_;
};

}
