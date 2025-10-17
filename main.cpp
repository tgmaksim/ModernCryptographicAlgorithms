#include <iostream>
#include <string>

#include "mca.h"
using namespace MCA;

static std::string inputstr(std::string text) {
    std::cout << text;
    std::string output;
    std::getline(std::cin, output);

    return output;
}

int main() {
    bool is_encrypt = inputstr("Input variant (encrypt, decrypt): ") == "encrypt";

    auto key = AES::generateKey();
    auto iv = AES::generateIV();

    std::string text;
    if (is_encrypt) {
        text = inputstr("Input text: ");
        std::string keyString = inputstr("Input key (hex) or keylength (128, 192, 256): ");

        if (keyString == "128" || keyString == "192" || keyString == "256")
            key = AES::generateKey(std::stoi(keyString) / 8);
        else {
            try {
                key = decodeBlockFromHex(keyString);
            }
            catch (const CryptoPP::Exception& e) {
                std::cerr << e.what() << std::endl;
            }
        }
    }
    else {
        text = inputstr("Input ciphertext (hex): ");
        std::string keyString = inputstr("Input key (hex): ");
        try {
            key = decodeBlockFromHex(keyString);
        }
        catch (const CryptoPP::Exception& e) {
            std::cerr << e.what() << std::endl;
        }
    }
    
    std::cout << "Key (hex): " << encodeToHex(key) << std::endl;

    std::string ivString;
    if (is_encrypt)
        ivString = inputstr("Input iv (hex) or skip to generate: ");
    else
        ivString = inputstr("Input iv (hex): ");
    
    if (!is_encrypt || !ivString.empty()) {
        try {
            iv = decodeBlockFromHex(ivString);
        }
        catch (const CryptoPP::Exception& e) {
            std::cerr << e.what() << std::endl;
        }
    }
    
    std::cout << "IV (hex): " << encodeToHex(iv) << std::endl;

    AES aes(key, iv);

    if (is_encrypt)
        std::cout << encodeToHex(aes.encrypt(text)) << std::endl;
    else {
        try {
            std::cout << aes.decrypt(decodeFromHex(text)) << std::endl;
        }
        catch (const CryptoPP::Exception& e) {
            if (e.GetErrorType() == CryptoPP::Exception::ErrorType::DATA_INTEGRITY_CHECK_FAILED)
                std::cout << "Неверный ключ или вектор инициализации" << std::endl;
            else
                std::cerr << e.what() << std::endl;
        }
    }

    return 0;
}
