#include <iostream>
#include <fstream>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <ctime>

using namespace CryptoPP;

// Load the public key from a .bin file
Integer LoadPublicKey(const std::string& publicKeyFile, Integer& n) {
    Integer e;
    std::ifstream pubFile(publicKeyFile, std::ios::binary);
    if (pubFile.is_open()) {
        size_t sizeE = 1024;
        size_t sizeN = 1024;

        byte* bufferE = new byte[sizeE];
        byte* bufferN = new byte[sizeN];

        pubFile.read(reinterpret_cast<char*>(bufferE), sizeE);
        pubFile.read(reinterpret_cast<char*>(bufferN), sizeN);

        // Check if the file reading was successful
        if (pubFile.gcount() == sizeE && pubFile.gcount() == sizeN) {
            e.Decode(bufferE, sizeE);
            n.Decode(bufferN, sizeN);
        } else {
            std::cerr << "Error: Failed to read key file correctly." << std::endl;
            e = Integer::Zero();
            n = Integer::Zero();
        }

        delete[] bufferE;
        delete[] bufferN;
        pubFile.close();
    } else {
        std::cerr << "Error: Unable to open public key file." << std::endl;
        e = Integer::Zero();
        n = Integer::Zero();
    }
    return e;
}

// Load the signature from a .bin file
Integer LoadSignatureFromFile(const std::string& filename) {
    Integer signature;
    size_t sizeSig = 1024;
    byte* bufferSig = new byte[sizeSig];

    std::ifstream sigFile(filename, std::ios::binary);
    if (sigFile.is_open()) {
        sigFile.read(reinterpret_cast<char*>(bufferSig), sizeSig);
        // Check if the file reading was successful
        if (sigFile.gcount() == sizeSig) {
            signature.Decode(bufferSig, sizeSig);
        } else {
            std::cerr << "Error: Failed to read signature file correctly." << std::endl;
            signature = Integer::Zero(); // Invalidate the signature if file reading fails
        }
        sigFile.close();
    } else {
        std::cerr << "Error: Could not open '" << filename << "'." << std::endl;
        signature = Integer::Zero(); // Invalidate the signature if the file can't be opened
    }

    delete[] bufferSig;
    return signature;
}

// Hash the message using SHA256
std::string HashMessage(const std::string& message) {
    SHA256 hash;
    std::string digest;
    StringSource s(message, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    return digest;
}

// Verify the signature using public key
bool VerifySignature(const Integer& e, const Integer& n, const std::string& messageHash, const Integer& signature) {
    Integer messageInt((const byte*)messageHash.data(), messageHash.size());
    Integer decryptedSignature = a_exp_b_mod_c(signature, e, n); // Decrypted signature = signature^e mod n
    std::cout<<"message:"<<messageInt<<"\n";
    std::cout<<"decryptedSignature:"<<decryptedSignature<<"\n";
    return messageInt == decryptedSignature;
}

int main(int argc, char* argv[]) {
	clock_t startTime, endTime;
    double elapsed_time;
    startTime = clock();
    if (argc != 4) {
        std::cerr << "Usage: ./verify <public_key_file> <data_file> <signature_file>" << std::endl;
        return 1;
    }

    // Load the public key
    Integer n;
    Integer e = LoadPublicKey(argv[1], n);

    // Check if the public key was loaded correctly
    if (e.IsZero() || n.IsZero()) {
        std::cerr << "Error: Invalid public key." << std::endl;
        return 1;
    }

    // Load the message
    std::ifstream dataFile(argv[2]);
    std::string message((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());

    // Hash the message
    std::string messageHash = HashMessage(message);

    // Load the signature from the provided signature file
    Integer signature = LoadSignatureFromFile(argv[3]);

    // Check if the signature was loaded correctly
    if (signature.IsZero()) {
        std::cerr << "Error: Invalid signature." << std::endl;
        return 1;
    }

    // Verify the signature
    if (VerifySignature(e, n, messageHash, signature)) {
        std::cout << "Signature is valid." << std::endl;
    } else {
        std::cout << "Signature is invalid." << std::endl;
    }
    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime)/CLOCKS_PER_SEC*1000;
    std::cout << "Execution Cost = " << elapsed_time << " ms" << std::endl;
    return 0;
}
