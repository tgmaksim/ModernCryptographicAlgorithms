#include "mca.h"
using namespace MCA;

CryptoPP::SecByteBlock AES::generateBlock(size_t size) {
	CryptoPP::SecByteBlock block(size);
	rng.GenerateBlock(block, block.size());

	return block;
}

inline CryptoPP::SecByteBlock AES::generateKey(size_t size) {
	return generateBlock(size);
}

inline CryptoPP::SecByteBlock AES::generateIV(size_t size) {
	return generateBlock(size);
}

AES::AES(const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) : _key(key), _iv(iv) {
	_encryptor.SetKeyWithIV(_key, _key.size(), _iv, _iv.size());
	_decryptor.SetKeyWithIV(_key, _key.size(), _iv, _iv.size());
}

AES::AES(const CryptoPP::SecByteBlock& key) : AES::AES(key, generateIV()) {}

AES::AES() : AES::AES(generateKey(), generateIV()) {}

std::string AES::encrypt(const std::string& text) {
	std::string encrypted;
	CryptoPP::StringSource(
		text,
		true,
		new CryptoPP::AuthenticatedEncryptionFilter(
			_encryptor,
			new CryptoPP::StringSink(encrypted)
		)
	);

	return encrypted;
}

std::string AES::decrypt(const std::string& ciphertext) {
	std::string decrypted;

	CryptoPP::StringSource(
		ciphertext,
		true,
		new CryptoPP::AuthenticatedDecryptionFilter(
			_decryptor,
			new CryptoPP::StringSink(decrypted)
		)
	);

	return decrypted;
}
