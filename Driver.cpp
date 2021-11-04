// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
using std::exit;
/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::byte;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector;
using CryptoPP::BufferedTransformation;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
#include "assert.h"
#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;
/* Set _setmode()*/ 
#ifdef _WIN32
	#include <io.h>
	#include <fcntl.h>
#else
#endif

/* Save and load key */
void Save(const string& filename, const BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);

/* convert wstring to string */
string wstring_to_string (const wstring& str);
/* convert string to wstring */
wstring string_to_wstring (const string& str);

int main(int argc, char* argv[])
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
  	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	AutoSeededRandomPool prng;
	CryptoPP::byte key[16],rkey[16];
/* Input key from terminal*/
	string pkey;
	wstring wpkey;
	wcout<<"Please input key (16 bytes): ";
	getline(wcin,wpkey);
	pkey=wstring_to_string(wpkey);
	/* Reading key from  input screen*/
	StringSource ss(pkey, false);
	/* Create byte array space for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data to key*/
    ss.Detach(new Redirector(copykey));
    ss.Pump(16);  // Pump first 16 bytes

	byte iv[DES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	wstring wplain;
	string plain;
	wcout << "Input plaintex:";
	wcin.ignore();
	getline(wcin,wplain);
	plain=wstring_to_string(wplain);
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

    // cout << "key length: " << DES::DEFAULT_KEYLENGTH << endl;
    // cout << "block size: " << DES::BLOCKSIZE << endl;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

