#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <ios>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            auto inStream = std::ifstream(options.GetInputFile(), std::ios_base::binary);
            auto outStream = std::ofstream(options.GetOutputFile(), std::ios_base::binary);
            cryptoCtx.EncryptFile(inStream, outStream, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }
        case COMMAND_TYPE::DECRYPT: {
            auto inStream = std::ifstream(options.GetInputFile(), std::ios_base::binary);
            auto outStream = std::ofstream(options.GetOutputFile(), std::ios_base::binary);
            cryptoCtx.DecryptFile(inStream, outStream, options.GetPassword());
            std::print("File decoded successfully\n");
            break;
        }            
        case COMMAND_TYPE::CHECKSUM: {
            auto inStream = std::ifstream(options.GetInputFile(), std::ios_base::binary);
            auto checksum = cryptoCtx.CalculateChecksum(inStream);
            std::print("Checksum: {}\n", std::move(checksum));
            break;
        }
        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}