#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <ctime>

using namespace CryptoPP;

// Function to generate a large prime
Integer GenerateLargePrime(size_t bitSize) {
    AutoSeededRandomPool rng;
    Integer prime;
    do {
        prime.Randomize(rng, bitSize);
    } while (!IsPrime(prime));
    return prime;
}

// Function to generate the private key (d)
void GeneratePrivateKey(const Integer& phi, Integer& d) {
    AutoSeededRandomPool rng;
    do {
        d.Randomize(rng, 512); // Randomly generate private key d
    } while (!RelativelyPrime(d, phi)); // Ensure d is relatively prime to phi
}

// Function to save integers to a binary file
void SaveIntegersToFile(const std::string& filename, const Integer& a, const Integer& b) {
    size_t sizeA = 1024;
    size_t sizeB = 1024;

    byte* bufferA = new byte[sizeA];
    byte* bufferB = new byte[sizeB];

    a.Encode(bufferA, sizeA);
    b.Encode(bufferB, sizeB);

    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bufferA), sizeA);        // Write a
    file.write(reinterpret_cast<const char*>(bufferB), sizeB);        // Write b
    file.close();

    delete[] bufferA;
    delete[] bufferB;
}

// Function to generate public and private keys
void GenerateKeys() {
    size_t bitSize = 512;
    Integer p = GenerateLargePrime(bitSize);
    Integer q = GenerateLargePrime(bitSize);
    while (p == q) {
        q = GenerateLargePrime(bitSize);
    }

    Integer n = p * q;              // Modulus for both keys
    Integer phi = (p - 1) * (q - 1); // Euler's totient function

    // Generate private key d
    Integer d;
    GeneratePrivateKey(phi, d); // Use phi to generate d

    // Generate public key e
    Integer e = d.InverseMod(phi); // e is the modular inverse of d mod phi

    // Save keys to binary files
    SaveIntegersToFile("public_key.bin", e, n);
    SaveIntegersToFile("private_key.bin", d, n);

    std::cout << "Keys generated and saved to public_key.bin and private_key.bin." << std::endl;

    // Discard p, q, and phi by setting them to zero
    p = 0;
    q = 0;
    phi = 0;

    // Optional: Securely wipe p, q, and phi from memory by overwriting them
    std::memset(&p, 0, sizeof(p));
    std::memset(&q, 0, sizeof(q));
    std::memset(&phi, 0, sizeof(phi));
}

// Main function
int main() {
    clock_t startTime, endTime;
    double elapsed_time;
    startTime = clock();
    GenerateKeys();
    endTime = clock();
    elapsed_time = static_cast<double>(endTime - startTime) / CLOCKS_PER_SEC * 1000;
    std::cout << "Execution Cost = " << elapsed_time << " ms" << std::endl;
    return 0;
}
