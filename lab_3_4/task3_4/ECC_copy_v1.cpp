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
#include <assert.h>
#include <sstream>
#include <fcntl.h>
/* Convert string*/ 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;
#include <stdexcept>
using std::runtime_error;
#include <chrono>
using namespace std::chrono;
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue; 
CryptoPP::OID oid=ASN1::secp256r1(); 
CryptoPP::DL_GroupParameters_EC<ECP> curve256;

AutoSeededRandomPool rng;
Integer q,n;
//Integer x("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7h");
//Integer y("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fh");

ECP::Point P;
void SaveBase64(const string& filename, const BufferedTransformation& bt);
void Save(const string& filename, const BufferedTransformation& bt);
void LoadBase64(const string& filename, BufferedTransformation& bt);
void Load(const string& filename, BufferedTransformation& bt);
void KeyGen(const string& filenamekeypub, const string& filenamekeypri);
void Sign(const string& filename, const string& filenamekeypri,const string& filenamesignature);
bool Verify(const string& filename, const string& filenamekeypub, const string& filenamekeypri,const string& filenamesignature);
string hash_sha256(const std::string& msg);
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
int main(int argc, char* argv[])
{
    #ifdef __linux__
    setlocale(LC_ALL,"");
    #elif _WIN32
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
    #else
    #endif
    curve256.Initialize(oid);
    q=curve256.GetCurve().GetField().GetModulus();
    n=curve256.GetSubgroupOrder();
    P=curve256.GetSubgroupGenerator();
    //Integer x("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7h");
    //Integer y("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fh");
        // Creat point G
    //ECP::Point G(x,y);
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
            wcout << "Input name pubkey:";
            getline(wcin,wplain);
            plain=wstring_to_string(wplain);
            wstring wpri;
            string pri;
            wcout << "Input name prikey:";
            getline(wcin,wpri);
            pri=wstring_to_string(wpri);
            auto start = high_resolution_clock::now();
            KeyGen(pri,plain);
            auto stop = high_resolution_clock::now();
             auto duration = duration_cast<microseconds>(stop - start);
            float milliseconds = (float) duration.count() / 1000;
            wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
            break;
        }
        case 2:
        {
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
            //Sign("Chủ tịch Quốc hội Vương Đình Huệ","ec.privateaa.key","aaa");
            Sign(file,pri,plain);
         auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    float milliseconds = (float) duration.count() / 1000;
    wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
         }   break;
        case 3:
          {  //Verify("Chủ tịch Quốc hội Vương Đình Huệ","ec.publicaa.key","aaa");
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
            wstring wpub;
            string pub;
            wcout << "Input name pubkey:";
            getline(wcin,wpub);
            pub=wstring_to_string(wplain);
            auto start = high_resolution_clock::now();
           wcout<<"Verify the signature on m:" <<Verify(file,pub,pri,plain);
            auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    float milliseconds = (float) duration.count() / 1000;
    wcout << " -> Elapsed time for encryption: " << milliseconds << " milliseconds" << endl;
            break;
        }
    }
    }

bool Verify(const string& filename, const string& filenamekeypub, const string& filenamekeypri,const string& filenamesignature)
{
    //load publickey
    string s;
    //const string& path_public = "Public"+filenamekey+".key";
    FileSource(filenamekeypub.c_str(),true,new StringSink(s));
    HexDecoder decoder;
    decoder.Put((byte*)s.data(), s.size());
    decoder.MessageEnd();
    size_t len = decoder.MaxRetrievable();
    ECP::Point Q;
    Q.identity=false;
    Q.x.Decode(decoder,len/2);
    Q.y.Decode(decoder,len/2);
    cout <<"Public key Qx=" << std::hex << Q.x  << endl;
    cout << "Public key Qy=" << std::hex << Q.y  << endl;

    //load   signature
    string sign;
    FileSource(filenamesignature.c_str(),true,new StringSink(sign));
    HexDecoder decoder_sign;
    decoder_sign.Put((byte*)sign.data(), sign.size());
    decoder_sign.MessageEnd();
    size_t len_sign = decoder_sign.MaxRetrievable();
    ECP::Point sr;
    sr.identity=false;
    sr.x.Decode(decoder_sign,len_sign/2);
    sr.y.Decode(decoder_sign,len_sign/2);
    cout <<"key s=" << std::hex << sr.x  << endl;
    cout << "key r=" << std::hex << sr.y  << endl;
     Integer u1,u2,sign_,r;
     sign_= sr.x;
     r = sr.y ;

     //load private key
     string key;
       //FileSource("Private.key",new StringSink (key));
       StringSink sss(key);
       Load(filenamekeypri,sss);

       StringSource source_key(key,true,new HexDecoder);
       Integer d(source_key,source_key.MaxRetrievable());
       cout<<"Key";
        std::cout  << d<< std::endl;
    //verify
    std::string msg ;
        StringSink ssss(msg);
        Load(filename,ssss);
        std::cout <<hash_sha256(msg)<<endl;
        
        StringSource source(hash_sha256(msg),true,new HexDecoder);
        
        //change hash to hex in integer
        Integer H_m(source,source.MaxRetrievable());

        ModularArithmetic ma(n);

        u1 =  ma.Divide((H_m),sign_);
        u2 = ma.Divide((r),sign_);
        ECP::Point vx=curve256.GetCurve().ScalarMultiply(P,u1 + d*u2);
        cout<<std::hex<<vx.x <<endl;
        bool result = false;
        if (vx.x.Compare( r)==0){
            result=true;
            }
        assert( true == result );
        cout << "Verify the signature on m:" << result << endl;
        //cout<<vx.x.Compare( r)<< endl;
        return result;
} 
void Sign(const string& filename, const string& filenamekeypri,const string& filenamesignature)
{
       string key;
       //FileSource("Private.key",new StringSink (key));
       StringSink sss(key);
       Load(filenamekeypri,sss);

       StringSource source_key(key,true,new HexDecoder);
       Integer d(source_key,source_key.MaxRetrievable());
       //cout<<"Key";
        //std::cout  << d<< std::endl;

        ECP::Point P=curve256.GetSubgroupGenerator();// G point
        Integer k(rng, Integer::One(), q);
        Integer r;
        ECP::Point R=curve256.GetCurve().ScalarMultiply(P,k);
        cout<<"R.x"<<R.x<<endl;
        r=R.x;
        //cout<<"R.x"<<r<<endl;
        std::string msg ;
        StringSink ssss(msg);
        Load(filename,ssss);
        std::cout <<hash_sha256(msg)<<endl;
        
        StringSource source(hash_sha256(msg),true,new HexDecoder);
        
        //change hash to hex in integer
        Integer H_m(source,source.MaxRetrievable());
       
        
        std::cout << std::hex << H_m<< std::endl;
        Integer rd,k_1,w,u1,u2,s;
        ModularArithmetic ma(n);
        ModularArithmetic mq(q);
        s = ma.Divide((H_m + r*d),k);
        //ECP::Point sr(s,r);
        std::stringstream ss;
         ss<<std::hex<<s;
         string sssss = ss.str();
         //cout<<"SS"<<ssss;

         std::stringstream rr;
         rr<<std::hex<<r;
         string rrr = rr.str();
         cout<<"S"<<rrr;
        //cout<<"SRRRR"<<s<<endl<<"rRRRRR"<<r<<endl;
        //CryptoPP::HexEncoder pubFile(new CryptoPP::FileSink("signature.key"));
        //curve256.GetCurve().EncodePoint(pubFile,sr,true);
        StringSource(sssss+rrr,true,new FileSink(filenamesignature.c_str()));

}
void KeyGen(const string& filenamekeypub, const string& filenamekeypri)
{
    // AutoSeededRandomPool rng;
    Integer q;
    // CryptoPP::OID oid=ASN1::secp256r1(); 
    // CryptoPP::DL_GroupParameters_EC<ECP> curve256;
   //ECP::PrivateKey PrivateKey;
    //ECP::PublicKey PublicKey;
    
    // curve256.Initialize(oid);
        Integer n;
        n=curve256.GetSubgroupOrder();
        cout << "Subgroup Order n=" << n <<endl;
        cout <<"Prime number p=" <<curve256.GetCurve().GetField().GetModulus()<<endl;
        q=curve256.GetCurve().GetField().GetModulus();
        cout <<"Prime number p=" <<std::hex<<q<<endl;
        cout<<IsPrime(q)<<endl;
        Integer h;
        h= curve256.GetCofactor();
        cout <<"Cofactor h="<< h<<endl;
        Integer d(rng, Integer::One(), curve256.GetMaxExponent());
        cout<<"d  "<<d<<endl;
        std::cout <<"PrivateKey"<<endl<<d<<endl;
        std::cout <<"PublicKey"<<endl;
        ECP::Element Q = curve256.ExponentiateBase(d);
        ECP::Point P=curve256.GetSubgroupGenerator();// G point
        cout <<"Public key Qx=" << std::hex << Q.x  << endl;
        cout << "Public key Qy=" << std::hex << Q.y  << endl;
        // CryptoPP::HexEncoder pubFile(new CryptoPP::FileSink("Public.key"));
        //PublicKey.GetGroupParameters().GetCurve().EncodePoint(pubFile,
        //Q, true);
        // string bt;
        // StringSource source(bt,true);
        //curve256.GetCurve().EncodePoint(pubFile,Q,true);
        //Save("Public.key",bt);
        std::stringstream ss;
         ss<<std::hex<<d;
        //cout<<"SS"<<ss;
         string s = ss.str();
         //cout<<"SS"<<s;
        //StringSource source(ss,true);
        //Save("Private.key",StringSource(ss.str(),true));
        //HexEncoder(d);
         std::stringstream ssr;
         ssr<<std::hex<<Q.x;
         string ssss = ssr.str();


         std::stringstream rr;
         rr<<std::hex<<Q.y;
         string rrr = rr.str();
        StringSource(ssss+rrr,true,new FileSink(filenamekeypub.c_str())); 
        StringSource(ss.str(),true,new FileSink(filenamekeypri.c_str()));
        string temp = " Generated to "+filenamekeypub+" and "+filenamekeypri+" successfully!"; 
        wcout << string_to_wstring(temp);
}
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}
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