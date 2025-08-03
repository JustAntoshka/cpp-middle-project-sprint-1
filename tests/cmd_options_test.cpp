#include "boost/program_options/errors.hpp"
#include "cmd_options.h"
#include <gtest/gtest.h>

#include <string_view>
#include <vector>

using CryptoGuard::ProgramOptions;

const auto getArgcArgv = [](std::vector<std::string> &argv_storage) {
    std::vector<char *> argv;
    for (auto &&a : argv_storage) {
        argv.push_back(a.data());
    }
    return argv;
};

TEST(ProgramOptions, TestRequiredOption) {
    const auto test = [](std::vector<std::string> &&argv_storage) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        ASSERT_THROW(options.Parse(argv.size(), argv.data()), boost::program_options::required_option);
    };

    test({"program"});
    test({"program", "--command", "encrypt"});
    test({"program", "--command", "encrypt", "--input", "input.txt"});
    test({"program", "--command", "encrypt", "--output", "output.txt"});
    test({"program", "--command", "encrypt", "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt"});
    test({"program", "--command", "decrypt"});
    test({"program", "--command", "decrypt", "--input", "input.txt"});
    test({"program", "--command", "decrypt", "--output", "output.txt"});
    test({"program", "--command", "decrypt", "--password", "qwerty"});
    test({"program", "--command", "decrypt", "--input", "input.txt", "--output", "output.txt"});
    test({"program", "--command", "checksum"});
}

TEST(ProgramOptions, TestReqiredArgument) {
    const auto test = [](std::vector<std::string> &&argv_storage) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        ASSERT_THROW(options.Parse(argv.size(), argv.data()), boost::program_options::invalid_command_line_syntax);
    };

    test({"program", "--command", "--input", "input.txt", "--output", "output.txt", "--password"});

    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "--password", "qwerty", "--output"});
    test({"program", "--command", "encrypt", "--output", "output.txt", "--password", "qwerty", "--input"});

    test({"program", "--command", "decrypt", "--input", "input.txt", "--output", "output.txt", "--password"});
    test({"program", "--command", "decrypt", "--input", "input.txt", "--password", "qwerty", "--output"});
    test({"program", "--command", "decrypt", "--output", "output.txt", "--password", "qwerty", "--input"});

    test({"program", "--command", "checksum", "--input"});
}

TEST(ProgramOptions, TestHelp) {
    {
        std::vector<std::string> argv_storage{"program", "--help"};
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        ASSERT_NO_THROW(options.Parse(argv.size(), argv.data()));
    }
}

TEST(ProgramOptions, TestPositionalArguments) {
    const auto test = [](std::vector<std::string> &&argv_storage) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        ASSERT_THROW(options.Parse(argv.size(), argv.data()),
                     boost::program_options::too_many_positional_options_error);
    };

    test({"program", "--command", "encrypt", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password",
          "qwerty"});
    test({"program", "--command", "encrypt", "decrypt", "--input", "input.txt", "--output", "output.txt", "--password",
          "qwerty"});
    test({"program", "--command", "encrypt", "checksum", "--input", "input.txt", "--output", "output.txt", "--password",
          "qwerty"});
    test({"program", "--command", "checksum", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password",
          "qwerty"});

    test({"program", "--command", "encrypt", "--input", "input.txt", "input.txt", "--output", "output.txt",
          "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "input2.txt", "--output", "output.txt",
          "--password", "qwerty"});

    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "output.txt",
          "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "output2.txt",
          "--password", "qwerty"});

    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password", "qwerty",
          "qwerty"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password", "qwerty",
          "qwerty2"});

    test({"program", "--command", "checksum", "--input", "input.txt", "input.txt"});
    test({"program", "--command", "checksum", "--input", "input.txt", "input2.txt"});
}

TEST(ProgramOptions, TestMultipleOccurences) {
    const auto test = [](std::vector<std::string> &&argv_storage) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        ASSERT_THROW(options.Parse(argv.size(), argv.data()), boost::program_options::multiple_occurrences);
    };

    test({"program", "--command", "encrypt", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt",
          "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--command", "decrypt", "--input", "input.txt", "--output", "output.txt",
          "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--command", "checksum", "--input", "input.txt", "--output", "output.txt",
          "--password", "qwerty"});
    test({"program", "--command", "checksum", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt",
          "--password", "qwerty"});

    test({"program", "--command", "encrypt", "--input", "input.txt", "--input", "input.txt", "--output", "output.txt",
          "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "--input", "input2.txt", "--output", "output.txt",
          "--password", "qwerty"});

    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--output", "output.txt",
          "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--output",
          "output2.txt", "--password", "qwerty"});

    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password", "qwerty",
          "--password", "qwerty"});
    test({"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password", "qwerty",
          "--password", "qwerty2"});

    test({"program", "--command", "checksum", "--input", "input.txt", "--input", "input.txt"});
    test({"program", "--command", "checksum", "--input", "input.txt", "--input", "input2.txt"});
}

TEST(ProgramOptions, TestWrongCommand) {
    const auto test = [](std::vector<std::string> &&argv_storage) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        ASSERT_THROW(options.Parse(argv.size(), argv.data()), boost::program_options::validation_error);
    };

    test({"program", "--command", ".", "--input", "input.txt", "--output", "output.txt", "--password", "qwerty"});
    test({"program", "--command", "encryptWRONG", "--input", "input.txt", "--output", "output.txt", "--password",
          "qwerty"});
    test({"program", "--command", "decryptWRONG", "--input", "input.txt", "--output", "output.txt", "--password",
          "qwerty"});
    test({"program", "--command", "checksumWRONG", "--input", "input.txt"});
}

TEST(ProgramOptions, TestCorrectOptionCrypt) {
    const auto test = [](std::vector<std::string> &&argv_storage, ProgramOptions::COMMAND_TYPE cmd,
                         std::string_view input, std::string_view output, std::string_view password) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        options.Parse(argv.size(), argv.data());
        EXPECT_EQ(options.GetCommand(), cmd);
        EXPECT_EQ(options.GetInputFile(), input);
        EXPECT_EQ(options.GetOutputFile(), output);
        EXPECT_EQ(options.GetPassword(), password);
    };

    test({"program", "--password", "qwerty", "--output", "output.txt", "--input", "input.txt", "--command", "encrypt"},
         ProgramOptions::COMMAND_TYPE::ENCRYPT, "input.txt", "output.txt", "qwerty");
    test({"program", "--password", "qwerty", "--output", "output.txt", "--input", "input.txt", "--command", "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "qwerty");
}

TEST(ProgramOptions, TestCorrectOptionChecksum) {
    const auto test = [](std::vector<std::string> &&argv_storage, ProgramOptions::COMMAND_TYPE cmd,
                         std::string_view input) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        options.Parse(argv.size(), argv.data());
        EXPECT_EQ(options.GetCommand(), cmd);
        EXPECT_EQ(options.GetInputFile(), input);
    };

    test({"program", "--command", "checksum", "--input", "input.txt"}, ProgramOptions::COMMAND_TYPE::CHECKSUM,
         "input.txt");
}

TEST(ProgramOptions, TestDashes) {
    const auto test = [](std::vector<std::string> &&argv_storage, ProgramOptions::COMMAND_TYPE cmd,
                         std::string_view input) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        options.Parse(argv.size(), argv.data());
        EXPECT_EQ(options.GetCommand(), cmd);
        EXPECT_EQ(options.GetInputFile(), input);
    };

    test({"program", "--command", "checksum", "--input", "input.txt"}, ProgramOptions::COMMAND_TYPE::CHECKSUM,
         "input.txt");
}

TEST(ProgramOptions, TestSpecialSigns) {
    const auto test = [](std::vector<std::string> &&argv_storage, ProgramOptions::COMMAND_TYPE cmd,
                         std::string_view input, std::string_view output, std::string_view password) {
        std::vector<char *> argv = getArgcArgv(argv_storage);
        ProgramOptions options;
        options.Parse(argv.size(), argv.data());
        EXPECT_EQ(options.GetCommand(), cmd);
        EXPECT_EQ(options.GetInputFile(), input);
        EXPECT_EQ(options.GetOutputFile(), output);
        EXPECT_EQ(options.GetPassword(), password);
    };

    test({"program", "--password", "--dashed-password--", "--output", "output.txt", "--input", "input.txt", "--command",
          "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "--dashed-password--");
    test({"program", "--password", "-dashed-password-2-", "--output", "output.txt", "--input", "input.txt", "--command",
          "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "-dashed-password-2-");
    test({"program", "--password", "'quoted-password'", "--output", "output.txt", "--input", "input.txt", "--command",
          "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "'quoted-password'");
    test({"program", "--password", "'quoted-password", "--output", "output.txt", "--input", "input.txt", "--command",
          "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "'quoted-password");
    test({"program", "--password", "quoted-password'", "--output", "output.txt", "--input", "input.txt", "--command",
          "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "quoted-password'");
    test({"program", "--password", "\\", "--output", "output.txt", "--input", "input.txt", "--command", "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "\\");
    test({"program", "--password", "\n", "--output", "output.txt", "--input", "input.txt", "--command", "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "\n");
    test({"program", "--password", "\0", "--output", "output.txt", "--input", "input.txt", "--command", "decrypt"},
         ProgramOptions::COMMAND_TYPE::DECRYPT, "input.txt", "output.txt", "\0");
}
