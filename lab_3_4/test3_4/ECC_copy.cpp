//  Defines the entry point for the console application
/*ECC parameters p,a,b, P (or G), n, h where p=h.n*/

/* Source, Sink */
#include "cryptopp/filters.h"
#include "cryptopp/algparam.h" //isprime
using CryptoPP::AlgorithmParameters;
using CryptoPP::MakeParameters;
#include <cryptopp/cryptlib.h>
using CryptoPP::RandomNumberGenerator;
#include <ctime>
#include <iostream>
#include <string>
using namespace std;

/* Randomly generator*/
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;
#include "cryptopp/modarith.h"
using CryptoPP::ModularArithmetic;
#include <cryptopp/ecp.h>
#include <cryptopp/eccrypto.h>
using CryptoPP::ECP;    // Prime field p
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

/* standard curves*/
#include <cryptopp/asn.h>
#include <cryptopp/oids.h> // 
namespace ASN1 = CryptoPP::ASN1;
using CryptoPP::OID;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;
using CryptoPP::SHA256;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

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
#include <cryptopp/cryptlib.h>
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

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
#include <chrono>
using namespace std::chrono;

#include <sstream>
// CryptoPP::OID oid=ASN1::secp256r1(); 
// CryptoPP::DL_GroupParameters_EC<ECP> curve256;
// curve256.Initialize(oid);
// AutoSeededRandomPool rng;
// Integer q,n;
// q=curve384.GetCurve().GetField().GetModulus();
// n=curve384.GetSubgroupOrder();
void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);
void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);
void KeyGen(const string& filename);
void Sign(const string& filename, const string& filenamekey,const string& filenamesignature);
string hash_sha256(const std::string& msg);
int main(int argc, char* argv[])
{
    //KeyGen("aa");
    AutoSeededRandomPool rng;
    //prime number q;
    Integer q;
        // AlgorithmParameters params = MakeParameters("BitLength", 256)
        // ("RandomNumberType", Integer::PRIME);
        // q.GenerateRandom(rng, params);

        CryptoPP::OID oid=ASN1::secp256r1(); 
        /* Create curve */ 
        CryptoPP::DL_GroupParameters_EC<ECP> curve384;
        //CryptoPP::DL_GroupParameters_EC<ECP>::Element Element;
        curve384.Initialize(oid);
        Integer n;
        n=curve384.GetSubgroupOrder();
        cout << "Subgroup Order n=" << n <<endl;
        cout <<"Prime number p=" <<curve384.GetCurve().GetField().GetModulus()<<endl;
        q=curve384.GetCurve().GetField().GetModulus();
        cout <<"Prime number p=" <<q<<endl;
        cout<<IsPrime(q)<<endl;
        Integer h;
        h= curve384.GetCofactor();
        cout <<"Cofactor h="<< h<<endl;
        //Integer d(rng, Integer::One(), n);
        Integer d(rng, Integer::One(), curve384.GetMaxExponent());
        std::cout <<"PrivateKey"<<endl<<d<<endl;
        std::cout <<"PublicKey"<<endl;
        ECP::Element Q = curve384.ExponentiateBase(d);
        ECP::Point P=curve384.GetSubgroupGenerator();
        // ECP::Point Q=curve384.GetCurve().ScalarMultiply(P,d);
        // std::cout <<"PublicKey"<<endl;
        cout <<"Public key Qx=" << std::hex << Q.x  << endl;
        cout << "Public key Qy=" << std::hex << Q.y  << endl;

        std::string message ;
        StringSink ssss(message);
        Load("result.csv",ssss);
 
        //Signing
        // auto start = high_resolution_clock::now();
        Integer k(rng, Integer::One(), q);
        Integer r;
        ECP::Point R=curve384.GetCurve().ScalarMultiply(P,k);
       // cout<<"R.x"<<R.x<<endl;
        r=R.x;
        //cout<<"R.x"<<r<<endl;
        std::string msg = message;
        //std::cout <<hash_sha256(msg)<<endl;
        
        StringSource source(hash_sha256(msg),true,new HexDecoder);
        
        //change hash to hex in integer
        Integer H_m(source,source.MaxRetrievable());
       
        
        //std::cout << std::hex << H_m<< std::endl;
        Integer rd,k_1,w,u1,u2,s;
        ModularArithmetic ma(n);
        ModularArithmetic mq(q);
        s = ma.Divide((H_m + r*d),k);
        cout<<"S"<<s<<endl;
    //       auto stop = high_resolution_clock::now();
    //     auto duration = duration_cast<microseconds>(stop - start);
    // float milliseconds = (float) duration.count() / 1000;
    // wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
    
    auto start = high_resolution_clock::now();
        u1 =  ma.Divide((H_m),s);
        u2 = ma.Divide((r),s);
        ECP::Point vx=curve384.GetCurve().ScalarMultiply(P,u1 + d*u2);
        cout<<std::hex<<vx.x <<endl;
        cout<<vx.x.Compare( r)<< endl;
      
     auto stop = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(stop - start);
    float milliseconds = (float) duration.count() / 1000;
    wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
    
        
    }
// void Sign(const string& filename, const string& filenamekey,const string& filenamesignature)
// {
//         Integer q;
        
//         ECP::Point P=curve256.GetSubgroupGenerator();// G point
//         Integer k(rng, Integer::One(), q);
//         Integer r;
//         ECP::Point R=curve384.GetCurve().ScalarMultiply(P,k);
//         cout<<"R.x"<<R.x<<endl;
//         r=R.x;
//         cout<<"R.x"<<r<<endl;
//         std::string msg = "Yoda said, Do or do not. There is no try.";
//         std::cout <<hash_sha256(msg)<<endl;
        
//         StringSource source(hash_sha256(msg),true,new HexDecoder);
        
//         //change hash to hex in integer
//         Integer H_m(source,source.MaxRetrievable());
       
        
//         std::cout << std::hex << H_m<< std::endl;
//         Integer rd,k_1,w,u1,u2,s;
//         ModularArithmetic ma(n);
//         ModularArithmetic mq(q);
//         s = ma.Divide((H_m + r*d),k);
//         ECP::Point sr(s,r);
        
// }
// void KeyGen(const string& filename)
// {
//     // AutoSeededRandomPool rng;
//     Integer q;
//     // CryptoPP::OID oid=ASN1::secp256r1(); 
//     // CryptoPP::DL_GroupParameters_EC<ECP> curve256;
//    //ECP::PrivateKey PrivateKey;
//     //ECP::PublicKey PublicKey;
    
//     // curve256.Initialize(oid);
//         Integer n;
//         n=curve256.GetSubgroupOrder();
//         cout << "Subgroup Order n=" << n <<endl;
//         cout <<"Prime number p=" <<curve256.GetCurve().GetField().GetModulus()<<endl;
//         q=curve256.GetCurve().GetField().GetModulus();
//         cout <<"Prime number p=" <<q<<endl;
//         cout<<IsPrime(q)<<endl;
//         Integer h;
//         h= curve256.GetCofactor();
//         cout <<"Cofactor h="<< h<<endl;
//         Integer d(rng, Integer::One(), curve256.GetMaxExponent());
//         std::cout <<"PrivateKey"<<endl<<d<<endl;
//         std::cout <<"PublicKey"<<endl;
//         ECP::Element Q = curve256.ExponentiateBase(d);
//         ECP::Point P=curve256.GetSubgroupGenerator();// G point
//         cout <<"Public key Qx=" << std::hex << Q.x  << endl;
//         cout << "Public key Qy=" << std::hex << Q.y  << endl;
//         CryptoPP::HexEncoder pubFile(new CryptoPP::FileSink("Public.key"));
//         //PublicKey.GetGroupParameters().GetCurve().EncodePoint(pubFile,
//         //Q, true);
//         string bt;
//         StringSource source(bt,true);
//         curve256.GetCurve().EncodePoint(pubFile,Q,true);
//         //Save("Public.key",bt);
//         std::stringstream ss;
//         ss << std::hex<<d;
//         //StringSource source(ss,true);
//         Save("Private.key",StringSource(ss.str(),true));

// }

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
string hash_sha256(const std::string& msg)
{
    SHA256 hash;
    HexEncoder encoder(new FileSink(std::cout));
   
    std::string digest;
    //https://www.cryptopp.com/wiki/Hash_Functions
    StringSource s(msg, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    return digest;
}