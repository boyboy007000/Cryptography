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

string hash_sha256(const std::string& msg);
int main(int argc, char* argv[])
{
    AutoSeededRandomPool rng;
// Contruct  ECP(const Integer &modulus, const FieldElement &A, const FieldElement &B);
        // oid standard curver
        CryptoPP::OID oid=ASN1::secp521r1(); 
        /* Create curve */ 
        CryptoPP::DL_GroupParameters_EC<ECP> curve384;
        curve384.Initialize(oid);
        /* Get curve paramaters p, a, b, G, n, h*/
        cout <<"Cofactor h="<< curve384.GetCofactor()<<endl;
        cout << "Subgroup Order n=" <<curve384.GetSubgroupOrder()<<endl;
        cout <<"Gx="<<curve384.GetSubgroupGenerator().x <<endl;
        cout <<"Gy="<<curve384.GetSubgroupGenerator().y <<endl;
        cout <<"Coefficient  a=" <<curve384.GetCurve().GetA()<<endl;
        cout <<"Coefficient  b=" <<curve384.GetCurve().GetB()<<endl;
        //cout <<"Prime number p=" <<curve384.GetCurve().GetField()<<endl;
        /* Computation on Curve Add, double, scalar mutiplication*/
        ECP::Point G=curve384.GetSubgroupGenerator();
        ECP::Point Q=curve384.GetCurve().Double(G); // G+G;
        cout << "Qx=" << Q.x << endl;
        cout << "Qy=" << Q.y << endl;
        Integer r("3451");
        cout << "number r=" << r<<endl;
        ECP::Point H=curve384.GetCurve().ScalarMultiply(G,r); // rP;
        cout << "Hx=" << H.x << endl;
        cout << "Hy=" << H.y << endl;
        ECP::Point I=curve384.GetCurve().Add(Q,H); // Q+H=2G+3451G
        cout << "Ix=" << I.x << endl;
        cout << "Iy=" << I.y << endl;
        // Verify
        Integer r1("3453");
        cout << "number r1=" << r1 <<endl;
        ECP::Point I1=curve384.GetCurve().ScalarMultiply(G,r1); // r1.G;
        cout << "I1x=" << I1.x << endl;
        cout << "I1y=" << I1.y << endl;
        cout << curve384.GetCurve().Equal(I,I1) <<endl;
        std::string msg = "Yoda said, Do or do not. There is no try.";
        std::cout <<hash_sha256(msg)<<endl;

        //AutoSeededRandomPool rng;
        // std::cout <<rng;
        //Integer s(RandomNumberGenerator &rng, 1024);
        Integer q;
        AlgorithmParameters params = MakeParameters("BitLength", 256)
        ("RandomNumberType", Integer::PRIME);
        q.GenerateRandom(rng, params);
        ModularArithmetic ma(j);
        //x = curve384.GetSubgroupOrder();   
        //s.Randomize(rng,const &x);
        //Integer s(RandomNumberGenerator &prng, 4096);
        //std::cout <<s<<endl;
        //std::cout <<s * G;
        //random d in [1, n-1] private key
        Integer x(rng, Integer::One(), curve384.GetSubgroupOrder());
        std::cout <<"PrivateKey"<<endl;
        std::cout <<x<<endl;
        //PublicKey
        std::cout <<"PublicKey"<<endl;
        ECP::Point Qp=curve384.GetCurve().ScalarMultiply(G,x);
        cout << "Qpx=" << Qp.x << endl;
        cout << "Qpy=" << Qp.y << endl;

        Integer k(rng, Integer::One(), q);

        std::cout <<k<<endl;

        ECP::Point R=curve384.GetCurve().ScalarMultiply(G,k);

        cout << "Rx=" << R.x << endl;
        cout << "Ry=" << R.y << endl;

        ECP::Point Q=curve384.GetCurve().Double(G); // G+G;

        std::cout <<1/k<<endl;

        cout << std::hex << "Prime number p=" << curve384.GetGroupParameters().GetCurve().GetField().GetModulus()<<endl;
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