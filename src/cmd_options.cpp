#include "cmd_options.h"
#include <boost/program_options/detail/parsers.hpp>
#include <boost/program_options/errors.hpp>
#include <boost/program_options/option.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help,h", "produce help message")("command,c", po::value<std::string>(), "command")(
        "input,i", po::value<std::string>(&inputFile_),
        "input")("output,o", po::value<std::string>(&outputFile_),
                 "output")("password,p", po::value<std::string>(&password_), "password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::positional_options_description positional;
    po::variables_map vm;
    // po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::store(po::command_line_parser(argc, argv).options(desc_).positional(positional).run(), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << "\n";
        return;
    }

    if (vm.count("command") == 0)
        throw po::required_option("command");
    if (vm.count("command") > 1)
        throw po::multiple_occurrences();

    auto command = vm["command"].as<std::string>();

    auto commandIter = commandMapping_.find(command);
    if (commandIter == commandMapping_.end()) {
        throw po::validation_error(po::validation_error::invalid_option_value, command, "command");
    }

    command_ = commandIter->second;

    switch (command_) {
    case COMMAND_TYPE::ENCRYPT:
    case COMMAND_TYPE::DECRYPT:
        if (auto cmd = "input"; vm.count(cmd) == 0)
            throw po::required_option(cmd);
        if (auto cmd = "output"; vm.count(cmd) == 0)
            throw po::required_option(cmd);
        if (auto cmd = "password"; vm.count(cmd) == 0)
            throw po::required_option(cmd);
        if (vm.count("input") > 1)
            throw po::multiple_occurrences();
        if (vm.count("output") > 1)
            throw po::multiple_occurrences();
        if (vm.count("password") > 1)
            throw po::multiple_occurrences();
        // inputFile_ = vm["input"].as<std::vector<std::string>>()[0];
        // outputFile_ = vm["output"].as<std::vector<std::string>>()[0];
        // password_ = vm["password"].as<std::vector<std::string>>()[0];
        break;
    case COMMAND_TYPE::CHECKSUM:
        if (auto cmd = "input"; vm.count(cmd) == 0)
            throw po::required_option(cmd);
        if (vm.count("input") > 1)
            throw po::multiple_occurrences();
        // inputFile_ = vm["input"].as<std::vector<std::string>>()[0];
        break;
    default:
        throw std::runtime_error{"Unsupported command"};
    }
}

}  // namespace CryptoGuard
