#pragma once

#include <experimental/propagate_const>
#include <memory>
#include <string>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = delete;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = delete;

    // API
    void EncryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const;
    void DecryptFile(std::istream &inStream, std::ostream &outStream, std::string_view password) const;
    std::string CalculateChecksum(std::istream &inStream) const;

private:
    class Impl;
    std::experimental::propagate_const<std::unique_ptr<Impl>> pImpl;
};

}  // namespace CryptoGuard
