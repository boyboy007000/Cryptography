#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;
using CryptoPP::SHA256;
#include <iostream>
#include "cryptopp/files.h" // File input, output
using CryptoPP::FileSink;
using CryptoPP::FileSource;
#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
#include <string>
using std::wstring;
using std::string;
string hash_sha256(const std::string& msg);
int main (int argc, char* argv[])
{
    using namespace CryptoPP;

    SHA256 hash;	
    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash.DigestSize() << std::endl;
    std::cout << "Block size: " << hash.BlockSize() << std::endl;

    std::string msg = "Yoda said, Do or do not. There is no try.";
    std::cout <<hash_sha256(msg);

//     HexEncoder encoder(new FileSink(std::cout));

// 	std::string msg = "Yoda said, Do or do not. There is no try.";
// 	std::string digest;

// //SHA256 hash;
// 	hash.Update((const byte*)msg.data(), msg.size());
// 	digest.resize(hash.DigestSize());
// 	hash.Final((byte*)&digest[0]);

// 	std::cout << "Message: " << msg << std::endl;

// 	std::cout << "Digest: ";
// 	StringSource(digest, true, new Redirector(encoder));
// 	std::cout << std::endl;
    return 0; 
}

string hash_sha256(const std::string& msg)
{
    SHA256 hash;
    HexEncoder encoder(new FileSink(std::cout));
    //std::string msg = "Yoda said, Do or do not. There is no try.";
    std::string digest;
    //hash.Update((const byte*)msg.data(), msg.size());
    //digest.resize(hash.DigestSize());
    

    //hash.Final((byte*)&digest[0]);

    std::cout << "Message: " << msg << std::endl;

    std::cout << "Digest: ";
    //StringSource(digest, true, new Redirector(encoder));
    StringSource s(msg, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    // StringSource ss( source, true /* PumpAll */,
    //              new HashFilter( hash, 
    //                new HexEncoder( 
    //                  new StringSink( value )
    //                ) // HexEncoder
    //              ) // HashFilter
    //           ); // StringSource

    //std::cout << digest<<std::endl;
    return digest;
}