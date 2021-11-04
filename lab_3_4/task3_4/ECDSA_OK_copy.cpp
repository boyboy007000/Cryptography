// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
//

#include <assert.h>

#include <string>
using std::wstring;
using std::string;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;
using std::cout;
using std::cin;
using std::ws;
#include "cryptopp/osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
#include "cryptopp/nbtheory.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::byte;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "cryptopp/oids.h"
using CryptoPP::OID;
// Hex encode, decode
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/queue.h>
using CryptoPP::ByteQueue; 

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
#include <fcntl.h>
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
#include <chrono>
using namespace std::chrono;
#include <stdexcept>
using std::runtime_error;
 // Funtions
bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey );
void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA256>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, SHA256>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA256>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA256>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA256>::PublicKey& key );
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature );
void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);
void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);
void KeyGen(const string& filename);
void Sign(const string& filename, const string& filenamekey, const  string& filenamesignature);
void Verify(const string& filename, const string& filenamekey, const string& filenamesignature);
//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{
    #ifdef __linux__
    setlocale(LC_ALL,"");
    #elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif
    string signature;
    //Sign("result.csv","ec.privateaa.key","aaa");
    //Verify("result.csv","ec.publicaa.key","aaa");
    // Choose encryption or decryption function.
    wcout << " Choose option:\n 1> Key generation\n 2> Sign\n 3> Verify\n ";
    //Sign();
    int option;
    wcin >> option;
    wcin.ignore();
    //cin.ignore();
    
    switch (option) {
        case 1:{
            wstring wplain;
            string plain;
            wcout << "Input name key:";
            getline(wcin,wplain);
            plain=wstring_to_string(wplain);
            auto start = high_resolution_clock::now();
            KeyGen(plain);
            auto stop = high_resolution_clock::now();
             auto duration = duration_cast<microseconds>(stop - start);
    float milliseconds = (float) duration.count() / 1000;
    wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
    
            break;
        }
        case 2:
        {
            //Sign("Chủ tịch Quốc hội Vương Đình Huệ","ec.privateaa.key","aaa");
        
        wstring wplain;
            string plain;
            wcout << "Input name signature:";
            getline(wcin,wplain);
            plain=wstring_to_string(wplain);
            wstring wpri;
            string pri;
            wcout << "Input name prikey:";
            getline(wcin,wpri);
            pri=wstring_to_string(wpri);
            wstring wfile;
            string file;
            wcout << "Input name file:";
            getline(wcin,wfile);
            file=wstring_to_string(wfile);
            auto start = high_resolution_clock::now();
            Sign(file,pri,plain);
            auto stop = high_resolution_clock::now();
             auto duration = duration_cast<microseconds>(stop - start);
    float milliseconds = (float) duration.count() / 1000;
    wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
    
            break;
        }
        case 3:
        {
            //Verify("Chủ tịch Quốc hội Vương Đình Huệ","ec.publicaa.key","aaa");
            wstring wplain;
            string plain;
            wcout << "Input name signature:";
            getline(wcin,wplain);
            plain=wstring_to_string(wplain);
            wstring wfile;
            string file;
            wcout << "Input name file:";
            getline(wcin,wfile);
            file=wstring_to_string(wfile);
            wstring wfilename;
            string filename;
                wcout << " Input public key\'s filename: ";
    getline(wcin >> ws, wfilename);
    filename = wstring_to_string(wfilename);
            auto start = high_resolution_clock::now();
            Verify(file,filename,plain);
            auto stop = high_resolution_clock::now();
             auto duration = duration_cast<microseconds>(stop - start);
            float milliseconds = (float) duration.count() / 1000;
             wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
            
            break;
        }
    }
    return 0;
}


////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
/* Def functions*/
void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}
void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
    Base64Encoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}
void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadBase64(const string& filename, BufferedTransformation& bt)
{
    Base64Decoder decoder;
    //string encoded;
    Load(filename,decoder);
    //decoder.Attach( new StringSink( decoded ) );
    //decoder.Put( (byte*)encoded.data(), encoded.size() );
    //decoder.MessageEnd();
    decoder.TransferTo(bt);
    bt.MessageEnd();
    //throw runtime_error("Not implemented");
}

void Sign(const string& filename, const string& filenamekey,const string& filenamesignature)
{
    //cout<<"Hello";
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    LoadPrivateKey( filenamekey, privateKey);
    //cout << std::hex << "Prime number p=" << privateKey.GetGroupParameters().GetCurve().GetField().GetModulus()<<endl;
    //cout << "Secret key d:" << std::hex << privateKey.GetPrivateExponent() << endl;
    string signature, encode, message;
    StringSink sss(message);
    Load(filename,sss);
    //string message = filename;
    AutoSeededRandomPool prng;
    signature.erase();    
    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA256>::Signer(privateKey),
            new Base64Encoder(new StringSink(signature))
        )
    );
    cout << "signature (r,s):" << signature << endl;
    //filenamesignature = signature;
    //StringSink ss(signature);
    //SaveBase64(filenamesignature,StringSource(signature),true));
    Save(filenamesignature,StringSource(signature,true));
}
void Verify(const string& filename, const string& filenamekey,const string& filenamesignature)
{
    //cout << "signature (r,s):" << filenamesignature << endl;
    //wcout<<"load public key";
    ECDSA<ECP, SHA256>::PublicKey publicKey_r;
    LoadPublicKey(filenamekey, publicKey_r);
    //wcout<<"load public key";
    string message_r ;
    string signature ;
    StringSink ssss(message_r);
    Load(filename,ssss);
    StringSink sss(signature);
    //StringSource(signature,true,new StringSink(signature)); 
    Load(filenamesignature,sss);
    //StringSource(queue,true,new StringSink(signature));
    //cout << "signature (r,s):" << signature << endl;
    string signature_r;
    StringSource ss(signature, true,
    new Base64Decoder(
        new StringSink(signature_r)
        ) // HexDecoder
    ); //
    bool result = false;
    result = VerifyMessage(publicKey_r, message_r, signature_r);
    assert( true == result );
    cout << "Verify the signature on m:" << result << endl;
}
void KeyGen(const string& filename)
{
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    bool result = false;
    result = GeneratePrivateKey( CryptoPP::ASN1::secp256r1(), privateKey );
    assert( true == result );
    if( !result ) { wcout<< "FAILED"; }
    result = GeneratePublicKey( privateKey, publicKey );
    assert( true == result );
    if( !result ) { wcout <<"FAILED"; }
    SavePrivateKey( "ec.private_"+filename+".key", privateKey );
    SavePublicKey( "ec.public_"+filename+".key", publicKey );
    string ss = " Generated to 'ec.private_"+filename+".key' and 'ec.public_"+filename+".key' successfully!"; 
    wcout << string_to_wstring(ss);
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA256>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
     
    return key.Validate( prng, 3 );
}

bool GeneratePublicKey( const ECDSA<ECP, SHA256>::PrivateKey& privateKey, ECDSA<ECP, SHA256>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void PrintDomainParameters( const ECDSA<ECP, SHA256>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA256>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA256>::PrivateKey& key )
{   
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA256>::PublicKey& key )
{   
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl; 
    cout << " Y: " << key.GetPublicElement().y << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA256>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA256>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA256>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA256>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA256>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA256>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );

    return result;
}
