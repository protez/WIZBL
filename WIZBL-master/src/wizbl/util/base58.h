// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Why base-58 instead of standard base-64 encoding?
 * - Don't want 0OIl characters that look the same in some fonts and
 *      could be used to create visually identical looking data.
 * - A string with non-alphanumeric characters is not as easily accepted as input.
 * - E-mail usually won't line-break if there's no punctuation to break at.
 * - Double-clicking selects the whole string as one word if it's all alphanumeric.
 */
#ifndef WIZBL_BASE58_H
#define WIZBL_BASE58_H

#include "wizbl/blockchain/chainparams.h"
#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "support/allocators/zeroafterfree.h"

#include <string>
#include <vector>

/**
 * Encode a byte sequence as a base58-encoded string.
 * pbegin and pend cannot be nullptr, unless both are.
 */
std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);

/**
 * Encode a byte vector as a base58-encoded string
 */
std::string EncodeBase58(const std::vector<unsigned char>& vch);

/**
 * Decode a base58-encoded string (psz) into a byte vector (vchRet).
 * return true if decoding is successful.
 * psz cannot be nullptr.
 */
bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet);

/**
 * Decode a base58-encoded string (str) into a byte vector (vchRet).
 * return true if decoding is successful.
 */
bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet);

/**
 * Encode a byte vector into a base58-encoded string, including checksum
 */
std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn);

/**
 * Decode a base58-encoded string (psz) that includes a checksum into a byte
 * vector (vchRet), return true if decoding is successful
 */
inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet);

/**
 * Decode a base58-encoded string (str) that includes a checksum into a byte
 * vector (vchRet), return true if decoding is successful
 */
inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet);

/**
 * Base class for all base58-encoded data
 */
class BLBase58Data {
protected:
    //! the version byte(s)
    std::vector<unsigned char> vchVersion;

    //! the actually encoded data
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData;

    BLBase58Data();
    void setData(const std::vector<unsigned char> &vchVersionIn, const void* pdata, size_t nSize);
    void setData(const std::vector<unsigned char> &vchVersionIn, const unsigned char *pbegin, const unsigned char *pend);

public:
    bool setString(const char* psz, unsigned int nVersionBytes = 1);
    bool setString(const std::string& str);
    std::string ToString() const;
    int CompareTo(const BLBase58Data& b58) const;

    bool operator==(const BLBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator<=(const BLBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const BLBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const BLBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const BLBase58Data& b58) const { return CompareTo(b58) >  0; }
};

/** base58-encoded Wizbl addresses.
 * Public-key-hash-addresses have version 0 (or 111 testnet).
 * The data vector contains RIPEMD160(SHA256(pubkey)), where pubkey is the serialized public key.
 * Script-hash-addresses have version 5 (or 196 testnet).
 * The data vector contains RIPEMD160(SHA256(cscript)), where cscript is the serialized redemption script.
 */
class CWizblAddress : public BLBase58Data {
public:
    bool set(const CKeyID &id);
    bool set(const CScriptID &id);
    bool set(const CTxDestination &dest);
    bool set(const CKeyID &id, const WBLChainParams &params);
    bool set(const CScriptID &id, const WBLChainParams &params);
    bool set(const CTxDestination &dest, const WBLChainParams &params);
    bool IsValid() const;
    bool IsValid(const WBLChainParams &params) const;

    CWizblAddress() {}
    CWizblAddress(const CTxDestination &dest) { set(dest); }
    CWizblAddress(const CTxDestination &dest, const WBLChainParams &params) { set(dest, params); }
    CWizblAddress(const std::string& strAddress) { setString(strAddress); }
    CWizblAddress(const char* pszAddress) { setString(pszAddress); }

    CTxDestination get() const;
    CTxDestination get(const WBLChainParams &params) const;
    bool getKeyID(CKeyID &keyID) const;
    bool getKeyID(CKeyID &keyID, const WBLChainParams &params) const;
    bool IsScript() const;
};

/**
 * A base58-encoded secret key
 */
class CWizblSecret : public BLBase58Data {
public:
    void setKey(const CKey& vchSecret);
    CKey getKey();
    bool IsValid() const;
    bool setString(const char* pszSecret);
    bool setString(const std::string& strSecret);

    CWizblSecret(const CKey& vchSecret) { setKey(vchSecret); }
    CWizblSecret() {}
};

template<typename K, int Size, WBLChainParams::Base58Type Type> class CWizblExtKeyBase : public BLBase58Data {
public:
    void setKey(const K &key) {
        unsigned char vch[Size];
        key.Encode(vch);
        setData(Params().Base58Prefix(Type), vch, vch+Size);
    }

    K getKey() {
        K ret;
        if (vchData.size() == Size) {
            // If base58 encoded data does not hold an ext key, return a !IsValid() key
            ret.Decode(vchData.data());
        } return ret;
    }

    CWizblExtKeyBase(const K &key) {
        setKey(key);
    }

    CWizblExtKeyBase(const std::string& strBase58c) {
        setString(strBase58c.c_str(), Params().Base58Prefix(Type).size());
    }

    CWizblExtKeyBase() {}
};

typedef CWizblExtKeyBase<CExtKey, BIP32_EXTKEY_SIZE, WBLChainParams::EXT_SECRET_KEY> CWizblExtKey;
typedef CWizblExtKeyBase<CExtPubKey, BIP32_EXTKEY_SIZE, WBLChainParams::EXT_PUBLIC_KEY> CWizblExtPubKey;

#endif // WIZBL_BASE58_H
