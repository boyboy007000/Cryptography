// ECDSA.KeyGen.cpp : Defines the entry point for the console application.
//

#include <assert.h>

#include <iostream>
using std::cout;
using std::endl;using std::wcout;
#include <string>
using std::string;

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

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;
#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
#include <chrono>
using namespace std::chrono;
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

bool SignMessage( const ECDSA<ECP, SHA256>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA256>::PublicKey& key, const string& message, const string& signature );
void Load(const string& filename, BufferedTransformation& bt);
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
    // Scratch result
    bool result = false;   
    
    // Private and Public keys
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;
    
    /////////////////////////////////////////////
    // Generate Keys
    result = GeneratePrivateKey( CryptoPP::ASN1::secp256r1(), privateKey );
    // assert( true == result );
    // if( !result ) { return -1; }

    result = GeneratePublicKey( privateKey, publicKey );
    // assert( true == result );
    // if( !result ) { return -2; }
    
    // Load key in PKCS#9 and X.509 format     

    /////////////////////////////////////////////
    //Print Domain Parameters and Keys   
    PrintDomainParameters(publicKey );
    PrintPrivateKey( privateKey );
    PrintPublicKey( publicKey );
    
    /////////////////////////////////////////////
    //Save key in PKCS#9 and X.509 format, pem, der?    
    SavePrivateKey( "ec.private.key", privateKey );
    SavePublicKey( "ec.public.key", publicKey );
    
    /////////////////////////////////////////////
    std::string msg ;
        StringSink ssss(msg);
        Load("Task 3.txt",ssss);

    /////////////////////////////////////////////
    // Print Domain Parameters and Keys    
    // PrintDomainParameters( publicKey );
    // PrintPrivateKey( privateKey );
    // PrintPublicKey( publicKey );
        
    /////////////////////////////////////////////
    // Sign and Verify a message      
    string message = msg;
    //cout << "input message :"<< message << endl;
    string signature, encode;

    // Pretty print signature
    AutoSeededRandomPool prng;
    // Load secret key
    LoadPrivateKey( "ec.private.key", privateKey);
    // Print parameters //
    cout << std::hex << "Prime number p=" << privateKey.GetGroupParameters().GetCurve().GetField().GetModulus()<<endl;
    cout << "Secret key d:" << std::hex << privateKey.GetPrivateExponent() << endl;
    // Public keys:
    privateKey.MakePublicKey(publicKey);
    
    //Public poins:
    cout <<"Public key Qx=" << std::hex << publicKey.GetPublicElement().x << endl;
    cout << "Public key Qy=" << std::hex << publicKey.GetPublicElement().y << endl;
   // auto start = high_resolution_clock::now();
    //siging message
    signature.erase();    
    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA256>::Signer(privateKey),
            new Base64Encoder(new StringSink(signature))
        )
    );
// auto stop = high_resolution_clock::now();
//              auto duration = duration_cast<microseconds>(stop - start);
//             float milliseconds = (float) duration.count() / 1000;
//             wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
            
    /*  kG = (x1, y1), r=x1; s= 𝑘^-1(𝐻(𝑚)+𝑥.𝑟) mod 𝑛 *, h=1, r=s = 2n
    */
    
    cout << "signature (r,s):" << signature << endl;

    
    // Verify by any peope: input publicKey, message, signature=(r,s)
    // Edit: verifier parameters : Public key hex encoded; (r, s) hex encoded
    ECDSA<ECP, SHA256>::PublicKey publicKey_r;
    LoadPublicKey("ec.public.key", publicKey_r);
    string message_r=msg;
    // Hex decode signature
    auto start = high_resolution_clock::now();
    string signature_r;
    StringSource ss(signature, true,
    new Base64Decoder(
        new StringSink(signature_r)
        ) // HexDecoder
    ); //

    result = VerifyMessage(publicKey_r, message_r, signature_r);
    auto stop = high_resolution_clock::now();
             auto duration = duration_cast<microseconds>(stop - start);
            float milliseconds = (float) duration.count() / 1000;
            wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
            
    // assert( true == result );
    cout << "Verify the signature on m:" << result << endl;
    return 0;
}

void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}
////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
/* Def functions*/

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
