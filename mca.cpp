#include "mca.h"

std::string MCA::encodeToHex(const std::string& text) {
	std::string encoded;
	CryptoPP::StringSource(
		text,
		true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		)
	);

	return encoded;
}

std::string MCA::encodeToHex(const CryptoPP::SecByteBlock& block) {
	std::string encoded;
	CryptoPP::StringSource(
		block,
		block.size(),
		true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(encoded)
		)
	);

	return encoded;
}

CryptoPP::SecByteBlock MCA::decodeBlockFromHex(const std::string& encoded) {
	std::string decoded;
	CryptoPP::StringSource(
		encoded,
		true,
		new CryptoPP::HexDecoder(
			new CryptoPP::StringSink(decoded)
		)
	);

	return CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(decoded.data()), decoded.size());
}

std::string MCA::decodeFromHex(const std::string& encoded) {
	std::string decoded;
	CryptoPP::StringSource(
		encoded,
		true,
		new CryptoPP::HexDecoder(
			new CryptoPP::StringSink(decoded)
		)
	);

	return decoded;
}
