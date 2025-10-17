#pragma once

#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/gcm.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>

namespace MCA {

CryptoPP::AutoSeededRandomPool rng;

std::string encodeToHex(const std::string&);
std::string encodeToHex(const CryptoPP::SecByteBlock&);
CryptoPP::SecByteBlock decodeBlockFromHex(const std::string&);
std::string decodeFromHex(const std::string&);

class AES {
protected:
	CryptoPP::SecByteBlock _key, _iv;
	CryptoPP::GCM<CryptoPP::AES>::Encryption _encryptor;
	CryptoPP::GCM<CryptoPP::AES>::Decryption _decryptor;

	static CryptoPP::SecByteBlock generateBlock(size_t = CryptoPP::AES::BLOCKSIZE);

public:
	inline CryptoPP::SecByteBlock getKey() const noexcept { return _key; }
	inline CryptoPP::SecByteBlock getIV() const noexcept { return _iv; }

	static inline CryptoPP::SecByteBlock generateKey(size_t = CryptoPP::AES::MAX_KEYLENGTH);
	static inline CryptoPP::SecByteBlock generateIV(size_t = CryptoPP::AES::BLOCKSIZE);

	AES(const CryptoPP::SecByteBlock&, const CryptoPP::SecByteBlock&);
	AES(const CryptoPP::SecByteBlock&);
	AES();

	std::string encrypt(const std::string&);
	std::string decrypt(const std::string&);
};

class RSA {
protected:
	CryptoPP::InvertibleRSAFunction _privateParams;
	CryptoPP::RSA::PrivateKey _privateKey;
	CryptoPP::RSAES_OAEP_SHA_Encryptor _encryptor;
	CryptoPP::RSA::PublicKey _publicKey;

	void _initialize(CryptoPP::InvertibleRSAFunction);

public:
	static const size_t modulusBits = 2048;

	inline CryptoPP::RSA::PrivateKey getPrivateKey() const noexcept { return _privateKey; }
	inline CryptoPP::RSA::PublicKey getPublicKey() const noexcept { return _publicKey; }

	RSA(const size_t = modulusBits);
	RSA(const int& n, const int& e, const int& d);

	std::string encrypt(const std::string&);
	std::string decrypt(const std::string&);
};

class SHA {};
class DigitalSignature {};

}
