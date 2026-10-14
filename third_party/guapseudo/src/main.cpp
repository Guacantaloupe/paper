#include "guapseudo/analyzer.hpp"
#include "guapseudo/binary_image.hpp"
#include "guapseudo/pseudoc_printer.hpp"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

struct CommandLine {
    std::string input;
    std::string hex;
    std::string output;
    std::uint64_t base = 0x1000;
    std::uint64_t entry = 0;
    unsigned threads = 0;
    std::size_t max_function_bytes = 4096;
    bool entry_set = false;
    bool stats = false;
    bool help = false;
    guapseudo::DecoderBackend decoder_backend = guapseudo::DecoderBackend::Builtin;
};

std::uint64_t parse_integer(const std::string& value) {
    std::size_t consumed = 0;
    const auto parsed = std::stoull(value, &consumed, 0);
    if (consumed != value.size()) throw std::runtime_error("invalid integer: " + value);
    return parsed;
}

void print_usage(std::ostream& out) {
    out << "GuaPseudo-C 0.1.0 - fast multi-core x86-64 pseudo-C decompiler\n\n"
        << "Usage:\n"
        << "  guapseudo-c <binary> [options]\n"
        << "  guapseudo-c --hex \"55 48 89 e5 31 c0 c3\" [options]\n\n"
        << "Options:\n"
        << "  --hex TEXT              decode an inline raw x86-64 byte sequence\n"
        << "  --base ADDRESS          base address for raw/hex input (default: 0x1000)\n"
        << "  --entry ADDRESS         override entry point\n"
        << "  --threads N             worker count; default uses hardware concurrency\n"
        << "  --max-function-bytes N  stop a function after N bytes (default: 4096)\n"
        << "  --decoder MODE          auto, builtin, or objdump (full GNU x86 decoder)\n"
        << "  --output FILE           write pseudo-C to FILE\n"
        << "  --stats                 print analysis timing to stderr\n"
        << "  -h, --help              show this help\n";
}

CommandLine parse_args(int argc, char** argv) {
    CommandLine options;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        const auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("missing value for ") + name);
            return argv[++i];
        };
        if (argument == "-h" || argument == "--help") options.help = true;
        else if (argument == "--hex") options.hex = next("--hex");
        else if (argument == "--base") options.base = parse_integer(next("--base"));
        else if (argument == "--entry") {
            options.entry = parse_integer(next("--entry"));
            options.entry_set = true;
        } else if (argument == "--threads") {
            options.threads = static_cast<unsigned>(parse_integer(next("--threads")));
            if (options.threads == 0) throw std::runtime_error("--threads must be greater than zero");
        } else if (argument == "--max-function-bytes") {
            options.max_function_bytes = static_cast<std::size_t>(parse_integer(next("--max-function-bytes")));
            if (options.max_function_bytes == 0) throw std::runtime_error("--max-function-bytes must be greater than zero");
        } else if (argument == "--decoder") {
            const auto mode = next("--decoder");
            if (mode == "auto") options.decoder_backend = guapseudo::DecoderBackend::Auto;
            else if (mode == "builtin") options.decoder_backend = guapseudo::DecoderBackend::Builtin;
            else if (mode == "objdump") options.decoder_backend = guapseudo::DecoderBackend::Objdump;
            else throw std::runtime_error("--decoder must be auto, builtin, or objdump");
        } else if (argument == "--output") options.output = next("--output");
        else if (argument == "--stats") options.stats = true;
        else if (!argument.empty() && argument[0] != '-' && options.input.empty()) options.input = argument;
        else throw std::runtime_error("unknown argument: " + argument);
    }
    if (!options.help && options.hex.empty() && options.input.empty()) {
        throw std::runtime_error("an input binary or --hex is required");
    }
    return options;
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto options = parse_args(argc, argv);
        if (options.help) {
            print_usage(std::cout);
            return 0;
        }

        guapseudo::BinaryImage image;
        if (!options.hex.empty()) {
            image = guapseudo::BinaryImageLoader::load_hex(options.hex, options.base,
                                                           options.entry_set ? options.entry : options.base);
        } else {
            image = guapseudo::BinaryImageLoader::load_file(options.input, options.base);
        }
        if (options.entry_set) image.entry = options.entry;
        if (!image.contains(image.entry)) {
            throw std::runtime_error("entry point is outside the extracted code section");
        }

        guapseudo::AnalysisConfig config;
        config.thread_count = options.threads;
        config.max_function_bytes = options.max_function_bytes;
        config.show_stats = options.stats;
        config.decoder_backend = options.decoder_backend;

        const auto start_time = std::chrono::steady_clock::now();
        const auto result = guapseudo::ParallelAnalyzer().analyze(image, config);
        const auto end_time = std::chrono::steady_clock::now();

        if (options.output.empty()) {
            guapseudo::PseudoCPrinter().print(image, result, std::cout);
        } else {
            std::ofstream output(options.output, std::ios::binary);
            if (!output) throw std::runtime_error("cannot open output: " + options.output);
            guapseudo::PseudoCPrinter().print(image, result, output);
        }

        if (options.stats) {
            const auto elapsed = std::chrono::duration<double, std::milli>(end_time - start_time).count();
            std::cerr << "[GuaPseudo-C] functions=" << result.functions.size()
                      << " instructions=" << result.decoded_instructions
                      << " workers=" << result.worker_count
                      << " analysis_ms=" << std::fixed << std::setprecision(3) << elapsed << "\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "GuaPseudo-C error: " << error.what() << "\n\n";
        print_usage(std::cerr);
        return 2;
    }
}

