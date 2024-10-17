#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <ctime>

using namespace CryptoPP;

// Load the private key from a .bin file
Integer LoadPrivateKey(const std::string& privateKeyFile, Integer& n) {
    Integer d;
    std::ifstream privFile(privateKeyFile, std::ios::binary);
    if (privFile.is_open()) {
        size_t sizeD = 1024;
        size_t sizeN = 1024;

        byte* bufferD = new byte[sizeD];
        byte* bufferN = new byte[sizeN];

        privFile.read(reinterpret_cast<char*>(bufferD), sizeD);
        privFile.read(reinterpret_cast<char*>(bufferN), sizeN);
        d.Decode(bufferD, sizeD);
        n.Decode(bufferN, sizeN);

        delete[] bufferD;
        delete[] bufferN;
        privFile.close();
    }
    return d;
}

// Hash the message using SHA256
std::string HashMessage(const std::string& message) {
    SHA256 hash;
    std::string digest;
    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    return digest;
}

// Sign the message hash using private key
Integer SignMessage(const Integer& d, const Integer& n, const std::string& messageHash) {
    Integer messageInt((const byte*)messageHash.data(), messageHash.size());
    Integer signature = a_exp_b_mod_c(messageInt, d, n); // Signature = hash^d mod n
    return signature;
}

// Save signature to a .bin file
void SaveSignatureToFile(const std::string& filename, const Integer& signature) {
    size_t sizeSig = 1024;
    byte* bufferSig = new byte[sizeSig];
    signature.Encode(bufferSig, sizeSig);

    std::ofstream sigFile(filename, std::ios::binary);
    sigFile.write(reinterpret_cast<const char*>(bufferSig), sizeSig);
    sigFile.close();

    delete[] bufferSig;
}

int main(int argc, char* argv[]) {
	clock_t startTime, endTime;
    double elapsed_time;
    startTime = clock();
    if (argc != 3) {
        std::cerr << "Usage: ./sign <private_key_file> <data_file>" << std::endl;
        return 1;
    }

    // Load the private key
    Integer n;
    Integer d = LoadPrivateKey(argv[1], n);

    // Load the message
    std::ifstream dataFile(argv[2]);
    std::string message((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());

    // Hash the message
    std::string messageHash = HashMessage(message);

    // Sign the message hash
    Integer signature = SignMessage(d, n, messageHash);

    // Save the signature to a binary file
    SaveSignatureToFile("signature.bin", signature);

    std::cout << "Message signed and signature saved to 'signature.bin'." << std::endl;
    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime)/CLOCKS_PER_SEC*1000;
    std::cout << "Execution Cost = " << elapsed_time << " ms" << std::endl;
    return 0;
}
