#include "mca.h"
using namespace MCA;

void RSA::_initialize(CryptoPP::InvertibleRSAFunction privateParams) {
    _privateKey = CryptoPP::RSA::PrivateKey(privateParams);
    _publicKey = CryptoPP::RSA::PublicKey(privateParams);

    _encryptor = CryptoPP::RSAES_OAEP_SHA_Encryptor(_privateKey);
}

RSA::RSA(const size_t modulusBits = RSA::modulusBits) {
    CryptoPP::InvertibleRSAFunction privateParams;
    privateParams.Initialize(rng, modulusBits);

    _initialize(privateParams);
}

RSA::RSA(const int &n, const int &e, const int &d) {
    CryptoPP::InvertibleRSAFunction privateParams;
    privateParams.Initialize(n, e, d);

    _initialize(privateParams);
}

std::string RSA::encrypt(const std::string& text) {
    std::string encrypted;
    CryptoPP::StringSource(
        text,
        true,
        new CryptoPP::PK_EncryptorFilter(
            rng,
            _encryptor,
            new CryptoPP::StringSink(encrypted)
        )
    );

    return encrypted;
}
std::string RSA::decrypt(const std::string&) {

}
