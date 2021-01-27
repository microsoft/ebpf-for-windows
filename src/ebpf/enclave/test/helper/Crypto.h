#pragma once
#include <memory>
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <functional>
#pragma comment(lib, "Bcrypt.lib")

class Crypto
{
public:
    typedef std::vector<unsigned char> Blob;
    typedef Blob Property;
    typedef Blob KeyMaterial;
    typedef std::function<void(const char * Message, NTSTATUS Status)> LogFn;

    Crypto() = delete;
    ~Crypto() = delete;
    
    class Key {
    public:
        virtual ~Key() {}
        virtual void Encrypt(const Blob & Iv, const Blob & ClearText, Blob & CypherText) = 0;
        virtual void Decrypt(const Blob & Iv, const Blob & CypherText, Blob & ClearText) = 0;
        virtual void AuthEncrypt(const Blob & ClearText, Blob & CypherText) = 0;
        virtual void AuthDecrypt(const Blob & CypherText, Blob & ClearText) = 0;
    };

    typedef std::shared_ptr<Key> KeyPtr;
    class Algorithm {
    public:
        virtual ~Algorithm() {}
        virtual Property GetProperty(const wchar_t * Name) = 0;
        virtual void SetProperty(const wchar_t * Name, const Property & Value) = 0;
        virtual void SetProperty(const wchar_t * Name, const wchar_t * Value) = 0;
        virtual KeyPtr CreateSymetricKey(const KeyMaterial & Material) = 0;
        virtual size_t GetBlockLength() = 0;
        virtual void FillRandom(Blob::iterator Start, Blob::iterator End) = 0;
    };
    typedef std::shared_ptr<Algorithm> AlgorithmPtr;

    static AlgorithmPtr OpenAlgorithm(const wchar_t * Algorithm, LogFn = nullptr);
private:
    class AlgorithmImpl;

    class KeyImpl : public Key {
    public:
        KeyImpl(AlgorithmImpl & Algorithm, const KeyMaterial & Material);
        virtual ~KeyImpl();
        virtual void Encrypt(const Blob & Iv, const Blob & ClearText, Blob & CypherText);
        virtual void Decrypt(const Blob & Iv, const Blob & CypherText, Blob & ClearText);
        virtual void AuthEncrypt(const Blob & ClearText, Blob & CypherText);
        virtual void AuthDecrypt(const Blob & CypherText, Blob & ClearText);
        AlgorithmImpl & Algorithm;
        BCRYPT_KEY_HANDLE Handle;
        std::vector<unsigned char> KeyStorage;
        void LogError(const char * Message, NTSTATUS Status);
        BCRYPT_AUTH_TAG_LENGTHS_STRUCT AuthTagLengths;
        size_t BlockSize;
    };

    class AlgorithmImpl : public Algorithm {
    public:
        AlgorithmImpl(const wchar_t * Algorithm, LogFn Log);
        virtual ~AlgorithmImpl();
        virtual Property GetProperty(const wchar_t * Name);
        virtual void SetProperty(const wchar_t * Name, const Property & Value);
        virtual void SetProperty(const wchar_t * Name, const wchar_t * Value);
        virtual KeyPtr CreateSymetricKey(const KeyMaterial & Material);
        virtual size_t GetBlockLength();
        virtual void FillRandom(Blob::iterator Start, Blob::iterator End);
        BCRYPT_ALG_HANDLE Handle;
        void LogError(const char * Message, NTSTATUS Status);
        LogFn Log;
    };
};

