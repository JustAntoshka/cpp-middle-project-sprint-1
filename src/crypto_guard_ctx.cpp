#include "crypto_guard_ctx.h"

#include <array>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
private:
    constexpr static size_t IN_BUF_SIZE = 1024;
    constexpr static size_t OUT_BUF_SIZE = IN_BUF_SIZE + EVP_MAX_BLOCK_LENGTH;
    using InBuf = std::array<char, IN_BUF_SIZE>;
    using OutBuf = std::array<char, OUT_BUF_SIZE>;

    constexpr static auto EvpCipherCtxDeleter = [](EVP_CIPHER_CTX *ctx) {
        if (ctx)
            EVP_CIPHER_CTX_free(ctx);
    };
    using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(EvpCipherCtxDeleter)>;

    constexpr static auto EvpMdCtxDeleter = [](EVP_MD_CTX *ctx) {
        if (ctx)
            EVP_MD_CTX_free(ctx);
    };
    using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(EvpMdCtxDeleter)>;

private:
    std::string GetOpensslErrorString() const { return ERR_error_string(ERR_get_error(), nullptr); }

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) const {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void Crypt(std::istream &inStream, std::ostream &outStream, const AesCipherParams &params) const {
        if (!inStream) {
            throw std::ios_base::failure{"Failed to read from input"};
        }
        if (!outStream) {
            throw std::ios_base::failure{"Failed to write to output"};
        }

        auto pCtx = EvpCipherCtxPtr{EVP_CIPHER_CTX_new(), EvpCipherCtxDeleter};
        if (!pCtx) {
            throw std::runtime_error{GetOpensslErrorString()};
        }

        if (!EVP_CipherInit_ex2(pCtx.get(), params.cipher, params.key.data(), params.iv.data(), params.encrypt,
                                nullptr)) {
            throw std::runtime_error{GetOpensslErrorString()};
        }

        InBuf inBuf;
        OutBuf outBuf;
        int outlen = 0;
        auto inBufPtr = reinterpret_cast<const unsigned char *>(inBuf.data());
        auto outBufPtr = reinterpret_cast<unsigned char *>(outBuf.data());
        while (inStream.read(inBuf.data(), inBuf.size())) {
            if (!EVP_CipherUpdate(pCtx.get(), outBufPtr, &outlen, inBufPtr, inBuf.size())) {
                throw std::runtime_error{GetOpensslErrorString()};
            }

            if (!outStream.write(outBuf.data(), outlen)) {
                throw std::ios_base::failure{"Failed to write to output"};
            }
        }

        if (inStream.eof()) {
            if (!EVP_CipherUpdate(pCtx.get(), outBufPtr, &outlen, inBufPtr, inStream.gcount())) {
                throw std::runtime_error{GetOpensslErrorString()};
            }

            if (!outStream.write(outBuf.data(), outlen)) {
                throw std::ios_base::failure{"Failed to write to output"};
            }
        } else {
            throw std::ios_base::failure{"Failed to read from input"};
        }

        if (!EVP_CipherFinal_ex(pCtx.get(), outBufPtr, &outlen)) {
            throw std::runtime_error{GetOpensslErrorString()};
        }

        if (!outStream.write(outBuf.data(), outlen)) {
            throw std::ios_base::failure{"Failed to write to output"};
        }
    }

public:
    void Encrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) const {
        AesCipherParams params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;
        Crypt(inStream, outStream, params);
    }

    void Decrypt(std::istream &inStream, std::ostream &outStream, std::string_view password) const {
        AesCipherParams params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;
        Crypt(inStream, outStream, params);
    }

    std::string CalculateChecksum(std::istream &inStream) const {
        if (!inStream) {
            throw std::ios_base::failure{"Failed to read from input"};
        }

        InBuf inBuf;
        std::array<unsigned char, EVP_MAX_MD_SIZE> mdValue;
        unsigned int mdLen;

        constexpr std::string_view DIGEST_NAME = "SHA256";
        const EVP_MD *md = EVP_get_digestbyname(DIGEST_NAME.data());
        if (md == NULL) {
            throw std::runtime_error{GetOpensslErrorString()};
        }

        auto mdctx = EvpMdCtxPtr{EVP_MD_CTX_new(), EvpMdCtxDeleter};
        if (!mdctx) {
            throw std::runtime_error{GetOpensslErrorString()};
        }

        if (!EVP_DigestInit_ex2(mdctx.get(), md, NULL)) {
            throw std::runtime_error{GetOpensslErrorString()};
        }

        while (inStream.read(inBuf.data(), inBuf.size())) {
            if (!EVP_DigestUpdate(mdctx.get(), inBuf.data(), inBuf.size())) {
                throw std::runtime_error{GetOpensslErrorString()};
            }
        }

        if (inStream.eof()) {
            if (!EVP_DigestUpdate(mdctx.get(), inBuf.data(), inStream.gcount())) {
                throw std::runtime_error{GetOpensslErrorString()};
            }
        } else {
            throw std::runtime_error{"Failed to read from input"};
        }

        if (!EVP_DigestFinal_ex(mdctx.get(), mdValue.data(), &mdLen)) {
            throw std::runtime_error{GetOpensslErrorString()};
        }

        std::ostringstream outStream;
        for (auto it = mdValue.begin(); it != mdValue.begin() + mdLen; ++it) {
            outStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(*it);
        }
        return outStream.str();
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl(std::make_unique<CryptoGuardCtx::Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const {
    pImpl->Encrypt(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const {
    pImpl->Decrypt(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream &inStream) const {
    return pImpl->CalculateChecksum(inStream);
}

}  // namespace CryptoGuard
