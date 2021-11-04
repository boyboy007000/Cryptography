// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

/* Generate random bytes*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include <stdio.h>

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;
#include <fstream>
using namespace std;

#include <string>
using std::string;
using std::wstring;

/* Convert string*/
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#include <cstdlib>
using std::exit;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::byte;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector;

#include "cryptopp/des.h"
using CryptoPP::DES;

#include "cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;


#include "assert.h"

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

void DES_CBC_rand()
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
  	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	AutoSeededRandomPool prng,rng;
	//CryptoPP::byte key[8],rkey[8],kiv[8];

	byte key[DES::BLOCKSIZE];
	prng.GenerateBlock(key, sizeof(key));


	byte iv[DES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	wstring wplain;
	string plain;
	wcout << "Input plaintex:";
	//wcin.ignore();
	getline(wcin,wplain);
	plain=wstring_to_string(wplain);

	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

try
	{

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
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
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

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

		wcout << "recovered text: " << string_to_wstring(recovered)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}


}
void DES_CBC_screen()
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
  	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	CryptoPP::byte key[8],rkey[8],kiv[8];
/* Input key from terminal*/
	string pkey;
	wstring wpkey;
	wcout<<"Please input key (16 bytes): ";
	getline(wcin,wpkey);
	std::cin.ignore();
	pkey=wstring_to_string(wpkey);
	/* Reading key from  input screen*/
	StringSource ss(pkey, false);
	/* Create byte array space for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data to key*/
    ss.Detach(new Redirector(copykey));
    ss.Pump(8);  // Pump first 8 bytes

	//byte iv[DES::BLOCKSIZE];
	//prng.GenerateBlock(iv, sizeof(iv));
	//input IV from screen
	string ivkey;
	wstring wivkey;
	wcout<<"please input IV (16 bytes): ";
	getline(wcin,wivkey);
	std::cin.ignore();
	pkey=wstring_to_string(wivkey);
	StringSource ss1(ivkey, false);
	CryptoPP::ArraySink copykeyiv(kiv, sizeof(kiv));

	ss1.Detach(new Redirector(copykeyiv));
    ss1.Pump(8);  // Pump first 8 bytes


	wstring wplain;
	string plain;
	wcout << "Input plaintex:";
	//wcin.ignore();
	getline(wcin,wplain);
	plain=wstring_to_string(wplain);

	string cipher, encoded, recovered;
	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(kiv, sizeof(kiv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), kiv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
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
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), kiv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/


} 

void DES_CBC_file(string path)
{
	CryptoPP::byte key[8],rkey[8],kiv[8];
	// Read from the text file
  	wifstream MyReadFile(path);
	string pkey;
	wstring wpkey;
	getline(MyReadFile,wpkey);
	//std::cin.ignore();
	pkey=wstring_to_string(wpkey);
	/* Reading key from  input screen*/
	StringSource ss(pkey, false);
	/* Create byte array space for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data to key*/
    ss.Detach(new Redirector(copykey));
    ss.Pump(8);  // Pump first 8 bytes

	string ivkey;
	wstring wivkey;
	
	getline(MyReadFile,wivkey);
	//std::cin.ignore();
	pkey=wstring_to_string(wivkey);
	StringSource ss1(ivkey, false);
	CryptoPP::ArraySink copykeyiv(kiv, sizeof(kiv));

	ss1.Detach(new Redirector(copykeyiv));
    ss1.Pump(8);  // Pump first 8 bytes


	wstring wplain;
	string plain;
	wcout << "Input plaintex:";
	//wcin.ignore();
	getline(wcin,wplain);
	plain=wstring_to_string(wplain);

	string cipher, encoded, recovered;
	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(kiv, sizeof(kiv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), kiv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
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
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), kiv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

}
void rand_key_iv(byte key[],byte iv[])
{
	AutoSeededRandomPool prng,rng;
	//byte key[DES::BLOCKSIZE];
	prng.GenerateBlock(key, sizeof(key));


	//byte iv[DES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
}
void input_key_iv_screen(byte key[],byte kiv[])
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
  	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	//CryptoPP::byte key[8],rkey[8],kiv[8];
/* Input key from terminal*/
	string pkey;
	wstring wpkey;
	wcout<<"Please input key (16 bytes): ";
	getline(wcin,wpkey);
	std::cin.ignore();
	pkey=wstring_to_string(wpkey);
	/* Reading key from  input screen*/
	StringSource ss(pkey, false);
	/* Create byte array space for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data to key*/
    ss.Detach(new Redirector(copykey));
    ss.Pump(8);  // Pump first 8 bytes

	//byte iv[DES::BLOCKSIZE];
	//prng.GenerateBlock(iv, sizeof(iv));
	//input IV from screen
	string ivkey;
	wstring wivkey;
	wcout<<"please input IV (16 bytes): ";
	getline(wcin,wivkey);
	std::cin.ignore();
	pkey=wstring_to_string(wivkey);
	StringSource ss1(ivkey, false);
	CryptoPP::ArraySink copykeyiv(kiv, sizeof(kiv));

	ss1.Detach(new Redirector(copykeyiv));
    ss1.Pump(8);  // Pump first 8 bytes

}

void input_key_iv_file(byte key[],byte kiv[],string path)
{
		wifstream MyReadFile(path);
	string pkey;
	wstring wpkey;
	getline(MyReadFile,wpkey);
	//std::cin.ignore();
	pkey=wstring_to_string(wpkey);
	/* Reading key from  input screen*/
	StringSource ss(pkey, false);
	/* Create byte array space for key*/
	CryptoPP::ArraySink copykey(key, sizeof(key));
	/*Copy data to key*/
    ss.Detach(new Redirector(copykey));
    ss.Pump(8);  // Pump first 8 bytes

	string ivkey;
	wstring wivkey;
	
	getline(MyReadFile,wivkey);
	//std::cin.ignore();
	pkey=wstring_to_string(wivkey);
	StringSource ss1(ivkey, false);
	CryptoPP::ArraySink copykeyiv(kiv, sizeof(kiv));

	ss1.Detach(new Redirector(copykeyiv));
    ss1.Pump(8);  // Pump first 8 bytes

}
void DES_CBC(string plain2,string cipher2,string encoded2,string recovered2,byte key2[],byte iv2[])
{
	// Pretty print key
	encoded2.clear();
	StringSource(key2, sizeof(key2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded2) << endl;

	// Pretty print iv
	encoded2.clear();
	StringSource(iv2, sizeof(iv2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

try
	{

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain2, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher2)
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
	encoded2.clear();
	StringSource(cipher2, true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher2, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered2)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered2)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}
void DES_OFB(string plain2,string cipher2,string encoded2,string recovered2,byte key2[],byte iv2[])
{
	// Pretty print key
	encoded2.clear();
	StringSource(key2, sizeof(key2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded2) << endl;

	// Pretty print iv
	encoded2.clear();
	StringSource(iv2, sizeof(iv2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

try
	{

		OFB_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain2, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher2)
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
	encoded2.clear();
	StringSource(cipher2, true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

	try
	{
		OFB_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher2, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered2)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered2)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	
}

void DES_CFB(string plain2,string cipher2,string encoded2,string recovered2,byte key2[],byte iv2[])
{
	
	// Pretty print key
	encoded2.clear();
	StringSource(key2, sizeof(key2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded2) << endl;

	// Pretty print iv
	encoded2.clear();
	StringSource(iv2, sizeof(iv2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

try
	{

		CFB_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain2, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher2)
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
	encoded2.clear();
	StringSource(cipher2, true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CFB_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher2, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered2)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered2)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void DES_CTR(string plain2,string cipher2,string encoded2,string recovered2,byte key2[],byte iv2[])
{
	// Pretty print key
	encoded2.clear();
	StringSource(key2, sizeof(key2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded2) << endl;

	// Pretty print iv
	encoded2.clear();
	StringSource(iv2, sizeof(iv2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

try
	{

		CTR_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain2, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher2)
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
	encoded2.clear();
	StringSource(cipher2, true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CTR_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key2, sizeof(key2), iv2);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher2, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered2)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered2)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

}

void DES_ECB(string plain2,string cipher2,string encoded2,string recovered2,byte key2[])
{
	// Pretty print key
	encoded2.clear();
	StringSource(key2, sizeof(key2), true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded2) << endl;

	

	/*********************************\
	\*********************************/

try
	{

		 ECB_Mode< DES >::Encryption e;
    	e.SetKey( key2, sizeof(key2) );

    	// The StreamTransformationFilter adds padding
    	//  as required. ECB and CBC Mode must be padded
    	//  to the block size of the cipher.
    	StringSource ss1( plain2, true, 
        new StreamTransformationFilter( e,
            new StringSink( cipher2 )
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
	encoded2.clear();
	StringSource(cipher2, true,
		new HexEncoder(
			new StringSink(encoded2)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded2) << endl;

	/*********************************\
	\*********************************/

	try
	{
		 ECB_Mode< DES >::Decryption d;
    // ECB Mode does not use an IV
    d.SetKey( key2, sizeof(key2) );

    // The StreamTransformationFilter removes
    //  padding as required.
    StringSource ss3( cipher2, true, 
        new StreamTransformationFilter( d,
            new StringSink( recovered2 )
        ) // StreamTransformationFilter
    ); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered2)<< endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

}

int main(int argc, char* argv[])
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
  	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
	string plain2;string cipher2;string encoded2;string recovered2;
	byte key2[DES::BLOCKSIZE];
	byte iv2[DES::BLOCKSIZE];
	cout<<"choose option:\n1> Secret key and IV are randomly\n2> Input Secret Key and IV from screen\n3> Input Secret Key and IV from file\n";
	int option;
	//getline(cin,option);
	//scanf("%d",&option);
	wcin>>option;
	//cin >> ws;
	//cin.ignore();
	//cin.ignore(numeric_limits<streamsize>::max(), '\n');

	switch(option)
	{
		case 1:
		rand_key_iv(key2,iv2);
		break;
		case 2:
		input_key_iv_screen(key2,iv2);
		break;
		case 3:
		input_key_iv_file(key2,iv2,"test.txt");
		break;
	}
	//rand_key_iv(key2,iv2);
	//input_key_iv_screen(key2,iv2);
	//input_key_iv_file(key2,iv2,"test.txt");
	//cin.ignore();
	wstring wplain;
	//wcin.sync();
	wcout << "Input plaintex:";
	//wcin>>wplain;
	getline(wcin>>ws,wplain);
	//wcin.ignore();
	//cin.ignore();
	//cin.ignore(numeric_limits<streamsize>::max(), '\n');
	
	//getline(wcin,wplain);
	//wcin.ignore();
	//wcout<<wplain<<endl;
   // cin >> ws;

	plain2=wstring_to_string(wplain);
	//wcout << "recovered text: " << string_to_wstring(plain2)<< endl;
	cout<<"choose option:\n1> Mode CBC\n2> Mode ECB\n3> Mode OFB\n4> Mode CFB\n5> Mode CTR\n";
	int option1;
	wcin>>option1;
	switch(option1)
	{
		case 1:
		DES_CBC(plain2,cipher2,encoded2,recovered2,key2,iv2);
		break;
		case 2:
		DES_ECB(plain2,cipher2,encoded2,recovered2,key2);
		break;
		case 3:
		DES_OFB(plain2,cipher2,encoded2,recovered2,key2,iv2);
		break;
		case 4:
		DES_CFB(plain2,cipher2,encoded2,recovered2,key2,iv2);
		break;
		case 5:
		DES_CTR(plain2,cipher2,encoded2,recovered2,key2,iv2);
		break;

	}
	
	
	
	
	
	


// wstring wplain2;
// 	string plain2;
// 	wcout << "Input plaintex:";
// 	//wcin.ignore();
// 	getline(wcin,wplain2);
// 	plain2=wstring_to_string(wplain2);

// 	string cipher2, encoded2, recovered2;

// 	// Pretty print key
// 	encoded2.clear();
// 	StringSource(key2, sizeof(key2), true,
// 		new HexEncoder(
// 			new StringSink(encoded2)
// 		) // HexEncoder
// 	); // StringSource
// 	wcout << "key: " << string_to_wstring(encoded2) << endl;

// 	// Pretty print iv
// 	encoded2.clear();
// 	StringSource(iv2, sizeof(iv2), true,
// 		new HexEncoder(
// 			new StringSink(encoded2)
// 		) // HexEncoder
// 	); // StringSource
// 	wcout << "iv: " << string_to_wstring(encoded2) << endl;

// 	/*********************************\
// 	\*********************************/

// try
// 	{

// 		CBC_Mode< DES >::Encryption e;
// 		e.SetKeyWithIV(key2, sizeof(key2), iv2);

// 		// The StreamTransformationFilter removes
// 		//  padding as required.
// 		StringSource s(plain2, true, 
// 			new StreamTransformationFilter(e,
// 				new StringSink(cipher2)
// 			) // StreamTransformationFilter
// 		); // StringSource
// 	}
// 	catch(const CryptoPP::Exception& e)
// 	{
// 		cerr << e.what() << endl;
// 		exit(1);
// 	}

// 	/*********************************\
// 	\*********************************/

// 	// Pretty print
// 	encoded2.clear();
// 	StringSource(cipher2, true,
// 		new HexEncoder(
// 			new StringSink(encoded2)
// 		) // HexEncoder
// 	); // StringSource
// 	wcout << "cipher text: " << string_to_wstring(encoded2) << endl;

// 	/*********************************\
// 	\*********************************/

// 	try
// 	{
// 		CBC_Mode< DES >::Decryption d;
// 		d.SetKeyWithIV(key2, sizeof(key2), iv2);

// 		// The StreamTransformationFilter removes
// 		//  padding as required.
// 		StringSource s(cipher2, true, 
// 			new StreamTransformationFilter(d,
// 				new StringSink(recovered2)
// 			) // StreamTransformationFilter
// 		); // StringSource

// 		wcout << "recovered text: " << string_to_wstring(recovered2)<< endl;
// 	}
// 	catch(const CryptoPP::Exception& e)
// 	{
// 		cerr << e.what() << endl;
// 		exit(1);
// 	}









// 	//DES_CBC_rand();
// 	//DES_CBC_screen();
// 	//DES_CBC_file("test.txt");

// 	AutoSeededRandomPool prng,rng;
// 	CryptoPP::byte key[8],rkey[8],kiv[8];
// 	/* 
// 	Wite key to file 
// 	prng.GenerateBlock(rkey, sizeof(rkey));
// 	StringSource ss1(rkey,sizeof(rkey), true, new FileSink("AES_KEY.dat"));	
//     */
// 	byte key1[DES::BLOCKSIZE];
// 	prng.GenerateBlock(key1, sizeof(key1));
// 	/* Input key from terminal*/
// 	string pkey;
// 	wstring wpkey;
// 	wcout<<"Please input key (16 bytes): ";
// 	getline(wcin,wpkey);
// 	std::cin.ignore();
// 	pkey=wstring_to_string(wpkey);
// 	/* Reading key from  input screen*/
// 	StringSource ss(pkey, false);
// 	/* Create byte array space for key*/
// 	CryptoPP::ArraySink copykey(key, sizeof(key));
// 	/*Copy data to key*/
//     ss.Detach(new Redirector(copykey));
//     ss.Pump(8);  // Pump first 8 bytes

// 	//byte iv[DES::BLOCKSIZE];
// 	//prng.GenerateBlock(iv, sizeof(iv));
// 	//input IV from screen
// 	string ivkey;
// 	wstring wivkey;
// 	wcout<<"please input IV (16 bytes): ";
// 	getline(wcin,wivkey);
// 	std::cin.ignore();
// 	pkey=wstring_to_string(wivkey);
// 	StringSource ss1(ivkey, false);
// 	CryptoPP::ArraySink copykeyiv(kiv, sizeof(kiv));

// 	ss1.Detach(new Redirector(copykeyiv));
//     ss1.Pump(8);  // Pump first 8 bytes


// 	wstring wplain;
// 	string plain;
// 	wcout << "Input plaintex:";
// 	//wcin.ignore();
// 	getline(wcin,wplain);
// 	plain=wstring_to_string(wplain);

// 	string cipher, encoded, recovered;
// 	/*********************************\
// 	\*********************************/

// 	// Pretty print key
// 	encoded.clear();
// 	StringSource(key, sizeof(key), true,
// 		new HexEncoder(
// 			new StringSink(encoded)
// 		) // HexEncoder
// 	); // StringSource
// 	wcout << "key: " << string_to_wstring(encoded) << endl;

// 	// Pretty print iv
// 	encoded.clear();
// 	StringSource(kiv, sizeof(kiv), true,
// 		new HexEncoder(
// 			new StringSink(encoded)
// 		) // HexEncoder
// 	); // StringSource
// 	wcout << "iv: " << string_to_wstring(encoded) << endl;

// 	/*********************************\
// 	\*********************************/

// 	try
// 	{

// 		CTR_Mode< DES >::Encryption e;
// 		e.SetKeyWithIV(key, sizeof(key), kiv);

// 		// The StreamTransformationFilter removes
// 		//  padding as required.
// 		StringSource s(plain, true, 
// 			new StreamTransformationFilter(e,
// 				new StringSink(cipher)
// 			) // StreamTransformationFilter
// 		); // StringSource
// 	}
// 	catch(const CryptoPP::Exception& e)
// 	{
// 		cerr << e.what() << endl;
// 		exit(1);
// 	}

// 	/*********************************\
// 	\*********************************/

// 	// Pretty print
// 	encoded.clear();
// 	StringSource(cipher, true,
// 		new HexEncoder(
// 			new StringSink(encoded)
// 		) // HexEncoder
// 	); // StringSource
// 	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

// 	/*********************************\
// 	\*********************************/

// 	try
// 	{
// 		CTR_Mode< DES >::Decryption d;
// 		d.SetKeyWithIV(key, sizeof(key), kiv);

// 		// The StreamTransformationFilter removes
// 		//  padding as required.
// 		StringSource s(cipher, true, 
// 			new StreamTransformationFilter(d,
// 				new StringSink(recovered)
// 			) // StreamTransformationFilter
// 		); // StringSource

// 		wcout << "recovered text: " << string_to_wstring(recovered)<< endl;
// 	}
// 	catch(const CryptoPP::Exception& e)
// 	{
// 		cerr << e.what() << endl;
// 		exit(1);
// 	}

	/*********************************\
	\*********************************/

	return 0;

}

/* Function Definitions */
/* convert wstring to string */
string wstring_to_string (const wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
/* convert string to wstring */
wstring string_to_wstring (const string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}
