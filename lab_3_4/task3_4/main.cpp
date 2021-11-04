#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <string>
using std::wstring;
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;
using std::wifstream;
using std::ws;

#include <assert.h>
#ifdef _WIN32
    #include <io.h>
#elif __linux__
    #include <inttypes.h>
    #include <unistd.h>
    #define __int64 int64_t
    #define _close close
    #define _read read
    #define _lseek64 lseek64
    #define _O_RDONLY O_RDONLY
    #define _open open
    #define _lseeki64 lseek64
    #define _lseek lseek
    #define stricmp strcasecmp
#endif
#include <fcntl.h>
#include <locale>
using std::wstring_convert;

#include <codecvt>
using std::codecvt_utf8;
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include <chrono>
using namespace std::chrono;

/* Convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* Convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
	FileSink file(filename.c_str());
	bt.CopyTo(file);
	file.MessageEnd();
}

/* Writing private key to file */
void SavePrivateKey(const string& filename, const PrivateKey& key)
{
	ByteQueue queue;
	key.Save(queue);
	Save(filename, queue);
}

/* Writing public key to file */
void SavePublicKey(const string& filename, const PublicKey& key)
{
	ByteQueue queue;
	key.Save(queue);
	Save(filename, queue);
}

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true);
	file.TransferTo(bt);
	bt.MessageEnd();
}

/* Reading private key from file */
void LoadPrivateKey(const string& filename, PrivateKey& key)
{
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

/* Reading public key from file */
void LoadPublicKey(const string& filename, PublicKey& key)
{
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

/* Key generation */
void KeyGen() {
	AutoSeededRandomPool rng;
	
	RSA::PrivateKey rsaPrivate;
	rsaPrivate.GenerateRandomWithKeySize(rng, 3072);

	RSA::PublicKey rsaPublic(rsaPrivate);

	SavePrivateKey("rsa-private.key", rsaPrivate);
	SavePublicKey("rsa-public.key", rsaPublic);
	wcout << " Generated to \'rsa-private.key\' and \'rsa-public.key\' successfully!";
}

/* Encryption */
void Encryption() {
	wstring wplain, wfilename;
    string plain, cipher, filename;
    
	// Load public key from file
	wcout << " Input public key\'s filename: ";
	getline(wcin >> ws, wfilename);
	filename = wstring_to_string(wfilename);
    AutoSeededRandomPool rng;
    RSA::PublicKey publicKey;
    LoadPublicKey(filename, publicKey);

	// Get plaintext
    wcout << " Choose option:\n 1> From screen\n 2> From file\n ";
    int option;
    wcin >> option;
    switch (option) {
		case 1:
			wcout << " Input plaintext: ";
			getline(wcin >> ws, wplain);
			wcout << " Plaintext is " << wplain << endl;
			plain = wstring_to_string(wplain);
			break;
		case 2:
			wcout << " Input plaintext\'s filename: ";
			getline(wcin >> ws, wfilename);
			filename = wstring_to_string(wfilename);
			wifstream file(filename);
			file.imbue(std::locale(file.getloc(), new std::codecvt_utf8_utf16<wchar_t, 0x10ffff, std::consume_header>));
			getline(file, wplain);
			wcout << " Plaintext is " << wplain << endl;
			plain = wstring_to_string(wplain);
			break;
    }
    
    // Start timer
    auto start = high_resolution_clock::now();
	
	// RSA encryption
    RSAES_OAEP_SHA_Encryptor e(publicKey);
    StringSource(plain, true,
      new PK_EncryptorFilter(rng, e,
        new StringSink(cipher)
      )
    );
    
    // End timer
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start);
	float milliseconds = (float) duration.count() / 1000;
	wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
    
	// Print ciphertext to screen in HEX
	string encoded;
    StringSource(cipher, true,
      new HexEncoder(
        new StringSink(encoded)
      )
    );
    wcout << " => Ciphertext is " << string_to_wstring(encoded) << endl;
}


/* Decryption */
void Decryption() {
	wstring wcipher, wfilename;
    string cipher, plain, filename;
    
	// Load private key from file
	wcout << " Input private key\'s filename: ";
	getline(wcin >> ws, wfilename);
	filename = wstring_to_string(wfilename);
    AutoSeededRandomPool rng;
    RSA::PrivateKey privateKey;
    LoadPrivateKey(filename, privateKey);

	// Get ciphertext
    wcout << " Choose option:\n 1> From screen\n 2> From file\n ";
    int option;
    wcin >> option;
    switch (option) {
		case 1:
			wcout << " Input ciphertext: ";
			getline(wcin >> ws, wcipher);
			wcout << " Ciphertext is " << wcipher << endl;
			cipher = wstring_to_string(wcipher);
			break;
		case 2:
			wcout << " Input ciphertext\'s filename: ";
			getline(wcin >> ws, wfilename);
			filename = wstring_to_string(wfilename);
			wifstream file(filename);
			file.imbue(std::locale(file.getloc(), new std::codecvt_utf8_utf16<wchar_t, 0x10ffff, std::consume_header>));
			getline(file, wcipher);
			wcout << " Ciphertext is " << wcipher << endl;
			cipher = wstring_to_string(wcipher);
			break;
    }
    
    // Convert from HEX
    string decoded;
    StringSource(cipher, true,
      new HexDecoder(
        new StringSink(decoded)
      )
    );
    
    // Start timer
    auto start = high_resolution_clock::now();
	
	// RSA decryption
	RSAES_OAEP_SHA_Decryptor d(privateKey);
    StringSource(decoded, true,
      new PK_DecryptorFilter(rng, d,
        new StringSink(plain)
      )
    );
    
	// End timer
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start);
	float milliseconds = (float) duration.count() / 1000;
	wcout << " -> Elapsed time for decryption: " << milliseconds << " milliseconds" << endl;
	
	// Print plaintext to screen
	wcout << " => Plaintext is " << string_to_wstring(plain) << endl;
}

int main(int argc, char * argv[]) {
	// Set mode support Vietnamese
    #ifdef __linux__
    setlocale(LC_ALL, "");
    #elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif

	// Choose encryption or decryption function.
    wcout << " Choose option:\n 1> Key generation\n 2> Encryption\n 3> Decryption\n ";
    int option;
    wcin >> option;
    switch (option) {
    	case 1:
			KeyGen();
			break;
		case 2:
			Encryption();
			break;
		case 3:
			Decryption();
			break;
    }
	
    return 0;
}
