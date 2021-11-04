// Debug:
// g++ -g -ggdb -Wall -Wextra -Wno-unused -I. -I/usr/include/cryptopp rsa_kgen_prof.cpp -o rsa_kgen_prof.exe -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -I. -I/usr/include/cryptopp rsa_kgen_prof.cpp -o rsa_kgen_prof.exe -lcryptopp && strip --strip-symbols rsa_kgen_prof.exe

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using namespace std;

#include <string>
using std::string;

#include <iomanip>
using std::fixed;
using std::setprecision;

#include <sstream>
using std::stringstream;

#include <stdexcept>
using std::runtime_error;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/hrtimer.h>
using CryptoPP::TimerBase;
using CryptoPP::ThreadUserTimer;

int main(int argc, char** argv)
{
    try
    {
        int bits = 8192;
        if(argc >= 2)
        {
            bits = atoi(argv[1]);
        }

        if(bits < 0)
        {
            throw runtime_error("Specified modulus size is not valid");
        }

        // http://www.cryptopp.com/docs/ref/class_auto_seeded_random_pool.html
        AutoSeededRandomPool prng;

        // http://www.cryptopp.com/docs/ref/rsa_8h.html
        RSA::PrivateKey rsa;

        // http://www.cryptopp.com/docs/ref/class_thread_user_timer.html
        ThreadUserTimer timer(TimerBase::MILLISECONDS);

        timer.StartTimer();

        rsa.GenerateRandomWithKeySize(prng, bits);
        SavePrivateKey("rsa-private.key", rsa);
        unsigned long elapsed = timer.GetCurrentTimerValue();
        unsigned long ticks = timer.TicksPerSecond();
        unsigned long seconds = elapsed / ticks;
        
        // days, hours, minutes, seconds, 100th seconds
        unsigned int d=0, h=0, m=0, s=0, p=0;

        p = ((elapsed * 100) / ticks) % 100;
        s = seconds % 60;
        m = (seconds / 60) % 60;
        h = (seconds / 60 / 60) % 60;
        d = (seconds / 60 / 60 / 24) % 24;

        float fs = (seconds + ((float)p/100));

        stringstream ss;
 
        if(d) {
            ss << d << ((d == 1) ? " day, " : " days, ");
            goto print_hours;
        }

        if(h) {
            print_hours:
                ss << h << ((h == 1) ? " hour, " : " hours, ");
                goto print_minutes;
        }

        if(m) {
            print_minutes:
                 ss << m << ((m == 1) ? " minute, " : " minutes, ");
        }

        ss << s << ((s == 1) ? " second" : " seconds");        

        cout << "Elapsed time for " << bits << " RSA key: ";
        
        cout << fixed << setprecision(2) << fs << "s";
        if(seconds)   
          cout << " (" << ss.str() << ")";
        cout << endl;
    }

    catch(CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        return -2;
    }
    catch(std::exception& e)
    {
        cerr << e.what() << endl;
        return -1;
    }

    return 0;
}

const char valid_message[] = "VALIDMESSAGE123";

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void Save(const string& filename, const BufferedTransformation& bt)
{
    // http://www.cryptopp.com/docs/ref/class_file_sink.html
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void LoadPrivateKey(const string& filename, PrivateKey& key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;

    Load(filename, queue);
    key.Load(queue);    
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
    // http://www.cryptopp.com/docs/ref/class_byte_queue.html
    ByteQueue queue;

    Load(filename, queue);
    key.Load(queue);    
}

void Load(const string& filename, BufferedTransformation& bt)
{
    // http://www.cryptopp.com/docs/ref/class_file_source.html
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void save_key_to_buffer(const RSA::PublicKey& key, char* buffer) {
  memset(buffer, 0, MSG_LEN);
  Integer n = key.GetModulus();
  n.Encode((byte *)buffer, MSG_LEN);
}

void load_key_from_buffer(RSA::PublicKey& key, char* buffer) {
  Integer n((const byte*)buffer, MSG_LEN);
  key.Initialize(n, EXP);
}

void RSA_encrypt(char* from, char* to, RSA::PublicKey& key) {
  memset(to, 0, MSG_LEN);
  Integer m((const byte*)from, MSG_LEN);
  Integer c = key.ApplyFunction(m);
  c.Encode((byte*)to, MSG_LEN);
}

void RSA_decrypt(char* from, char* to, RSA::PrivateKey& key) {
  memset(to, 0, MSG_LEN);
  AutoSeededRandomPool rng;
  Integer c((const byte*)from, MSG_LEN);
  Integer r = key.CalculateInverse(rng, c);
  r.Encode((byte*)to, MSG_LEN);
}

// void AES_encrypt(char* buffer, int size, byte* key, byte* iv) {
//   CFB_Mode<AES>::Encryption enc(key, AES::DEFAULT_KEYLENGTH, iv);
//   enc.ProcessData((byte*) buffer, (byte*) buffer, size - 16);
// }

// void AES_decrypt(char* buffer, int size, byte* key, byte* iv) {
//   CFB_Mode<AES>::Decryption dec(key, AES::DEFAULT_KEYLENGTH, iv);
//   dec.ProcessData((byte*) buffer, (byte*) buffer, size - 16);
// }
  

// void generate_aes_key(byte* key, byte* iv) {
//   memset(key, 0, AES::DEFAULT_KEYLENGTH);
//   memset(iv, 0, AES::BLOCKSIZE);
//   AutoSeededRandomPool rnd;
//   rnd.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
//   rnd.GenerateBlock(iv, AES::BLOCKSIZE);
// }