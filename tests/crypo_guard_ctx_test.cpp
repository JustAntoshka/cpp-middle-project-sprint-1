#include "crypto_guard_ctx.h"
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <sstream>
#include <stdexcept>

TEST(CryptoGuardCtx, CheckCorrectPassword) {

    const auto test = [](std::string input, std::string password) {
        CryptoGuard::CryptoGuardCtx ctx;

        std::istringstream inStream{input};
        std::istringstream chksumStream{input};
        std::ostringstream outStream;

        auto inputChecksum = ctx.CalculateChecksum(chksumStream);
        ctx.EncryptFile(inStream, outStream, password);

        std::string encrypted = outStream.str();
        std::istringstream encryptedStream{encrypted};
        std::istringstream encryptedChksumStream{encrypted};
        std::ostringstream decryptedStream;

        auto encryptedChecksum = ctx.CalculateChecksum(encryptedChksumStream);
        ctx.DecryptFile(encryptedStream, decryptedStream, password);

        std::string decrypted = decryptedStream.str();
        std::istringstream decryptedChksumStream{decrypted};

        auto decryptedChecksum = ctx.CalculateChecksum(decryptedChksumStream);

        EXPECT_NE(encrypted, input);
        EXPECT_NE(encryptedChecksum, inputChecksum);

        EXPECT_EQ(decrypted, input);
        EXPECT_EQ(decryptedChecksum, inputChecksum);
    };

    test("", "qwerty123");
    test("", "");
    test("abcdefghijklmnopqrstuvwxyz\n", "");
    test("abcdefghijklmnopqrstuvwxyz\n", "qwerty123");
    test("123\n456\0789", "qwerty123");
    test(std::string(15, '0'), "qwerty123");
    test(std::string(16, '0'), "qwerty123");
    test(std::string(17, '0'), "qwerty123");
    test(std::string(31, '0'), "qwerty123");
    test(std::string(32, '0'), "qwerty123");
    test(std::string(33, '0'), "qwerty123");
    test(std::string(1023, '0'), "qwerty123");
    test(std::string(1024, '0'), "qwerty123");
    test(std::string(1025, '0'), "qwerty123");
    test(std::string(2047, '0'), "qwerty123");
    test(std::string(2048, '0'), "qwerty123");
    test(std::string(2049, '0'), "qwerty123");
}

TEST(CryptoGuardCtx, CheckWrongPassword) {
    const auto test = [](std::string input, std::string password, std::string wrongPassword) {
        CryptoGuard::CryptoGuardCtx ctx;

        std::istringstream inStream{input};
        std::ostringstream outStream;

        ctx.EncryptFile(inStream, outStream, password);

        std::string encrypted = outStream.str();
        std::istringstream encryptedStream{encrypted};
        std::ostringstream decryptedStream;

        ASSERT_THROW(ctx.DecryptFile(encryptedStream, decryptedStream, wrongPassword), std::runtime_error);
    };

    test("abcdefghijklmnopqrstuvwxyz", "qwerty", "!@#$%^&*");
    test("abcdefghijklmnopqrstuvwxyz", "", "!@#$%^&*");
    test("abcdefghijklmnopqrstuvwxyz", "qwerty", "");
    test("", "qwerty", "!@#$%^&*");
    test("", "", "!@#$%^&*");
    test("", "qwerty", "");
}

TEST(CryptoGuardCtx, CheckSubsequentCalls1) {

    const auto test = [](std::string input1, std::string password1, std::string input2, std::string password2) {
        CryptoGuard::CryptoGuardCtx ctx;

        std::istringstream inStream1{input1};
        std::istringstream inStream2{input2};
        std::ostringstream outStream1;
        std::ostringstream outStream2;

        ctx.EncryptFile(inStream1, outStream1, password1);
        ctx.EncryptFile(inStream2, outStream2, password2);

        std::string encrypted1 = outStream1.str();
        std::string encrypted2 = outStream2.str();
        std::istringstream encryptedStream1{encrypted1};
        std::istringstream encryptedStream2{encrypted2};
        std::ostringstream decryptedStream1;
        std::ostringstream decryptedStream2;

        ctx.DecryptFile(encryptedStream1, decryptedStream1, password1);
        ctx.DecryptFile(encryptedStream2, decryptedStream2, password2);

        EXPECT_EQ(decryptedStream1.str(), input1);
        EXPECT_EQ(decryptedStream2.str(), input2);
    };

    test("42", "qwerty123", "abcdefghijklmnopqrstuvwxyz", "+_)(*&^%$#@!)");
}

TEST(CryptoGuardCtx, CheckSubsequentCalls2) {
    const auto test = [](std::string input1, std::string password1, std::string input2, std::string password2) {
        CryptoGuard::CryptoGuardCtx ctx;

        std::istringstream inStream1{input1};
        std::ostringstream outStream1;

        ctx.EncryptFile(inStream1, outStream1, password1);
        std::string encrypted1 = outStream1.str();
        std::istringstream encryptedStream1{encrypted1};
        std::ostringstream decryptedStream1;
        ctx.DecryptFile(encryptedStream1, decryptedStream1, password1);

        std::istringstream inStream2{input2};
        std::ostringstream outStream2;

        ctx.EncryptFile(inStream2, outStream2, password2);
        std::string encrypted2 = outStream2.str();
        std::istringstream encryptedStream2{encrypted2};
        std::ostringstream decryptedStream2;
        ctx.DecryptFile(encryptedStream2, decryptedStream2, password2);

        EXPECT_EQ(decryptedStream1.str(), input1);
        EXPECT_EQ(decryptedStream2.str(), input2);
    };

    test("abcdefghijklmnopqrstuvwxyz", "+_)(*&^%$#@!)", "42", "qwerty123");
}

TEST(CryptoGuardCtx, CheckInStreamErrorEncrypt) {
    const auto test = [](std::istringstream &inStream, std::ios::iostate state) {
        CryptoGuard::CryptoGuardCtx ctx;
        std::ostringstream outStream;
        inStream.setstate(state);
        ASSERT_THROW(ctx.EncryptFile(inStream, outStream, "qwerty"), std::ios_base::failure);
    };

    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::badbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::badbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::badbit | std::ios::eofbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::eofbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::badbit | std::ios::eofbit);
    }
}
TEST(CryptoGuardCtx, CheckInStreamErrorDecrypt) {
    const auto test = [](std::istringstream &inStream, std::ios::iostate state) {
        CryptoGuard::CryptoGuardCtx ctx;
        std::ostringstream outStream;
        inStream.setstate(state);
        ASSERT_THROW(ctx.DecryptFile(inStream, outStream, "qwerty"), std::ios_base::failure);
    };

    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::badbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::badbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::badbit | std::ios::eofbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::eofbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::badbit | std::ios::eofbit);
    }
}
TEST(CryptoGuardCtx, CheckInStreamErrorChecksum) {
    const auto test = [](std::istringstream &inStream, std::ios::iostate state) {
        CryptoGuard::CryptoGuardCtx ctx;
        inStream.setstate(state);
        ASSERT_THROW(ctx.CalculateChecksum(inStream), std::ios_base::failure);
    };

    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::badbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::badbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::badbit | std::ios::eofbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::eofbit);
    }
    {
        std::istringstream inStream{"42"};
        test(inStream, std::ios::failbit | std::ios::badbit | std::ios::eofbit);
    }
}

TEST(CryptoGuardCtx, CheckOutStreamErrorEncrypt) {
    const auto test = [](std::ios::iostate state) {
        CryptoGuard::CryptoGuardCtx ctx;
        std::istringstream inStream{"42"};
        std::ostringstream outStream;
        outStream.setstate(state);
        ASSERT_THROW(ctx.EncryptFile(inStream, outStream, "qwerty"), std::ios_base::failure);
    };

    test(std::ios::badbit);
    test(std::ios::failbit);
    test(std::ios::failbit | std::ios::badbit);
    test(std::ios::badbit | std::ios::eofbit);
    test(std::ios::failbit | std::ios::eofbit);
    test(std::ios::failbit | std::ios::badbit | std::ios::eofbit);
}
TEST(CryptoGuardCtx, CheckOutStreamErrorDecrypt) {
    const auto test = [](std::ios::iostate state) {
        CryptoGuard::CryptoGuardCtx ctx;
        std::istringstream inStream{"42"};
        std::ostringstream outStream;
        outStream.setstate(state);
        ASSERT_THROW(ctx.DecryptFile(inStream, outStream, "qwerty"), std::ios_base::failure);
    };

    test(std::ios::badbit);
    test(std::ios::failbit);
    test(std::ios::failbit | std::ios::badbit);
    test(std::ios::badbit | std::ios::eofbit);
    test(std::ios::failbit | std::ios::eofbit);
    test(std::ios::failbit | std::ios::badbit | std::ios::eofbit);
}

TEST(CryptoGuardCtx, CheckChecksum) {
    const auto test = [](std::string &&input, std::string &&output) {
        CryptoGuard::CryptoGuardCtx ctx;
        std::istringstream inStream{input};
        EXPECT_EQ(ctx.CalculateChecksum(inStream), output);
    };

    test("42", "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049");
    test("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    test(std::string(15, '0'), "14bdcd6fd64180af5e7791df91b6af8e9a3e7bc844997eb8c29252706df97ca5");
    test(std::string(16, '0'), "fcdb4b423f4e5283afa249d762ef6aef150e91fccd810d43e5e719d14512dec7");
    test(std::string(17, '0'), "c1c0605291078b71f6fae716e2e497fe15ec1a977c269b2cb2229dfaf61f7a13");
    test(std::string(31, '0'), "f08d28edd4251370855e84d9cf7e522cea075eced0658086c33d9669ced0e6ea");
    test(std::string(32, '0'), "84e0c0eafaa95a34c293f278ac52e45ce537bab5e752a00e6959a13ae103b65a");
    test(std::string(33, '0'), "54f05a87f5b881780cdc40e3fddfebf72e3ba7e5f65405ab121c7f22d9849ab4");
    test(std::string(1023, '0'), "8f017d33568c8bad2c714c86c4418a1d21c7ce5a88f7f37622d423da5ada524e");
    test(std::string(1024, '0'), "35ae5091b37e8f0f306833ef57a635f9dc06738d7f4e563a610eec2adb26fe28");
    test(std::string(1025, '0'), "959fa8ba78fc16f09bb5ecba70627528e437233595c9f858d2697d2512060cee");
}

TEST(CryptoGuardCtx, CheckEncrypDecryptChecksum) {
    const auto test = [](std::string &&input, std::string &&output) {
        CryptoGuard::CryptoGuardCtx ctx;
        std::istringstream inStream{input};
        EXPECT_EQ(ctx.CalculateChecksum(inStream), output);
    };

    test("42", "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049");
    test("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    test(std::string(15, '0'), "14bdcd6fd64180af5e7791df91b6af8e9a3e7bc844997eb8c29252706df97ca5");
    test(std::string(16, '0'), "fcdb4b423f4e5283afa249d762ef6aef150e91fccd810d43e5e719d14512dec7");
    test(std::string(17, '0'), "c1c0605291078b71f6fae716e2e497fe15ec1a977c269b2cb2229dfaf61f7a13");
    test(std::string(31, '0'), "f08d28edd4251370855e84d9cf7e522cea075eced0658086c33d9669ced0e6ea");
    test(std::string(32, '0'), "84e0c0eafaa95a34c293f278ac52e45ce537bab5e752a00e6959a13ae103b65a");
    test(std::string(33, '0'), "54f05a87f5b881780cdc40e3fddfebf72e3ba7e5f65405ab121c7f22d9849ab4");
    test(std::string(1023, '0'), "8f017d33568c8bad2c714c86c4418a1d21c7ce5a88f7f37622d423da5ada524e");
    test(std::string(1024, '0'), "35ae5091b37e8f0f306833ef57a635f9dc06738d7f4e563a610eec2adb26fe28");
    test(std::string(1025, '0'), "959fa8ba78fc16f09bb5ecba70627528e437233595c9f858d2697d2512060cee");
}
