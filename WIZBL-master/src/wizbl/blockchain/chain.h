// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WIZBL_CHAIN_H
#define WIZBL_CHAIN_H

#include "wizbl/blockchain/util/arith_uint256.h"
#include "wizbl/blockchain/primitives/block.h"
#include "pow.h"
#include "wizbl/blockchain/util/tinyformat.h"
#include "wizbl/blockchain/util/uint256.h"

#include <vector>
#include <string.h>

/**
 * Maximum amount of time that a block timestamp is allowed to exceed the
 * current network-adjusted time before the block will be accepted.
 */
static const int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;

/**
 * Timestamp window used as a grace period by code that compares external
 * timestamps (such as timestamps passed to RPCs, or wallet key creation times)
 * to block timestamps. This should be set at least as high as
 * MAX_FUTURE_BLOCK_TIME.
 */
static const int64_t TIMESTAMP_WINDOW = MAX_FUTURE_BLOCK_TIME;

class BLBlockFileInfo {
public:
    unsigned int nBlocks;      //!< number of blocks stored in file
    unsigned int nSize;        //!< number of used bytes of block file
    unsigned int nUndoSize;    //!< number of used bytes in the undo file
    unsigned int nHeightFirst; //!< lowest height of block in file
    unsigned int nHeightLast;  //!< highest height of block in file
    uint64_t nTimeFirst;       //!< earliest time of block in file
    uint64_t nTimeLast;        //!< latest time of block in file

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nBlocks));
        READWRITE(VARINT(nSize));
        READWRITE(VARINT(nUndoSize));
        READWRITE(VARINT(nHeightFirst));
        READWRITE(VARINT(nHeightLast));
        READWRITE(VARINT(nTimeFirst));
        READWRITE(VARINT(nTimeLast));
    }

     void setNull() {
         nBlocks = 0;
         nSize = 0;
         nUndoSize = 0;
         nHeightFirst = 0;
         nHeightLast = 0;
         nTimeFirst = 0;
         nTimeLast = 0;
     }

     BLBlockFileInfo() {
         setNull();
     }

     std::string ToString() const;

     /** update statistics (does not update nSize) */
     void AddBlock(unsigned int nHeightIn, uint64_t nTimeIn) {
         if (nBlocks==0 || nHeightFirst > nHeightIn)
             nHeightFirst = nHeightIn;
         if (nBlocks==0 || nTimeFirst > nTimeIn)
             nTimeFirst = nTimeIn;
         nBlocks++;
         if (nHeightIn > nHeightLast)
             nHeightLast = nHeightIn;
         if (nTimeIn > nTimeLast)
             nTimeLast = nTimeIn;
     }
};

struct CDiskBlockPos {
    int nFile;
    unsigned int nPos;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(VARINT(nFile));
        READWRITE(VARINT(nPos));
    }

    CDiskBlockPos() {
        setNull();
    }

    CDiskBlockPos(int nFileIn, unsigned int nPosIn) {
        nFile = nFileIn;
        nPos = nPosIn;
    }

    friend bool operator==(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return (a.nFile == b.nFile && a.nPos == b.nPos);
    }

    friend bool operator!=(const CDiskBlockPos &a, const CDiskBlockPos &b) {
        return !(a == b);
    }

    void setNull() { nFile = -1; nPos = 0; }
    bool IsNull() const { return (nFile == -1); }

    std::string ToString() const {
        return strprintf("BLBlockDiskPos(nFile=%i, nPos=%i)", nFile, nPos);
    }

};

enum BlockStatus: uint32_t {
    //! Unused.
    BLOCK_VALID_UNKNOWN      =    0,

    //! Parsed, version ok, hash satisfies claimed PoW, 1 <= vtx count <= max, timestamp not in future
    BLOCK_VALID_HEADER       =    1,

    //! All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    //! are also at least TREE.
    BLOCK_VALID_TREE         =    2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, BLBlockIndex::nChainTx will be set.
     */
    BLOCK_VALID_TRANSACTIONS =    3,

    //! Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    //! Implies all parents are also at least CHAIN.
    BLOCK_VALID_CHAIN        =    4,

    //! Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    BLOCK_VALID_SCRIPTS      =    5,

    //! All validity bits.
    BLOCK_VALID_MASK         =   BLOCK_VALID_HEADER | BLOCK_VALID_TREE | BLOCK_VALID_TRANSACTIONS |
                                 BLOCK_VALID_CHAIN | BLOCK_VALID_SCRIPTS,

    BLOCK_HAVE_DATA          =    8, //!< full block available in blk*.dat
    BLOCK_HAVE_UNDO          =   16, //!< undo data available in rev*.dat
    BLOCK_HAVE_MASK          =   BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO,

    BLOCK_FAILED_VALID       =   32, //!< stage after last reached validness failed
    BLOCK_FAILED_CHILD       =   64, //!< descends from failed block
    BLOCK_FAILED_MASK        =   BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD,

    BLOCK_OPT_WITNESS       =   128, //!< block data in blk*.data was received with a witness-enforcing client
};

/** The block chain is a tree shaped structure starting with the
 * genesis block at the root, with each block potentially having multiple
 * candidates to be the next block. A blockindex may have multiple pprev pointing
 * to it, but at most one of them can be part of the currently active branch.
 */
class BLBlockIndex {
public:
    //! pointer to the hash of the block, if any. Memory is owned by this BLBlockIndex
    const uint256* phashBlock;

    //! pointer to the index of the predecessor of this block
    BLBlockIndex* pprev;

    //! pointer to the index of some further predecessor of this block
    BLBlockIndex* pskip;

    //! height of the entry in the chain. The genesis block has height 0
    int nHeight;

    //! Which # file this block is stored in (blk?????.dat)
    int nFile;

    //! Byte offset within blk?????.dat where this block's data is stored
    unsigned int nDataPos;

    //! Byte offset within rev?????.dat where this block's undo data is stored
    unsigned int nUndoPos;

    //! (memory only) Total amount of work (expected number of hashes) in the chain up to and including this block
    arith_uint256 nChainWork;

    //! Number of transactions in this block.
    //! Note: in a potential headers-first mode, this number cannot be relied upon
    unsigned int nTx;

    //! (memory only) Number of transactions in the chain up to and including this block.
    //! This value will be non-zero only if and only if transactions for this block and all its parents are available.
    //! Change to 64-bit type when necessary; won't happen before 2030
    unsigned int nChainTx;

    //! Verification status of this block. See enum BlockStatus
    unsigned int nStatus;

    //! block header
    int nVersion;
    uint256 hashMerkleRoot;
    uint32_t nReserved[7];
    unsigned int nTime;
    unsigned int nBits;
    uint256 nNonce;
    std::vector<unsigned char> nSolution;

    //! (memory only) Sequential id assigned to distinguish order in which blocks are received.
    int32_t nSequenceId;

    //! (memory only) Maximum nTime in the chain upto and including this block.
    unsigned int nTimeMax;

    void setNull() {
        phashBlock = nullptr;
        pprev = nullptr;
        pskip = nullptr;
        nHeight = 0;
        nFile = 0;
        nDataPos = 0;
        nUndoPos = 0;
        nChainWork = arith_uint256();
        nTx = 0;
        nChainTx = 0;
        nStatus = 0;
        nSequenceId = 0;
        nTimeMax = 0;

        nVersion       = 0;
        hashMerkleRoot = uint256();
        memset(nReserved, 0, sizeof(nReserved));
        nTime          = 0;
        nBits          = 0;
        nNonce         = uint256();
        nSolution.clear();
    }

    BLBlockIndex() {
        setNull();
    }

    BLBlockIndex(const BLBlockHeader& block) {
        setNull();

        nVersion       = block.nVersion;
        hashMerkleRoot = block.hashMerkleRoot;
        // TODO(h4x3rotab): Copy nHeight or not?
        nHeight        = block.nHeight;
        memcpy(nReserved, block.nReserved, sizeof(nReserved));
        nTime          = block.nTime;
        nBits          = block.nBits;
        nNonce         = block.nNonce;
        nSolution      = block.nSolution;
    }

    CDiskBlockPos getBlockPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_DATA) {
            ret.nFile = nFile;
            ret.nPos  = nDataPos;
        } return ret;
    }

    CDiskBlockPos getUndoPos() const {
        CDiskBlockPos ret;
        if (nStatus & BLOCK_HAVE_UNDO) {
            ret.nFile = nFile;
            ret.nPos  = nUndoPos;
        } return ret;
    }

    BLBlockHeader getBlockHeader() const {
        BLBlockHeader block;
        block.nVersion       = nVersion;
        if (pprev)
            block.hashPrevBlock = pprev->getBlockHash();
        block.hashMerkleRoot = hashMerkleRoot;
        block.nHeight        = nHeight;
        memcpy(block.nReserved, nReserved, sizeof(block.nReserved));
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.nSolution      = nSolution;
        return block;
    }

    uint256 getBlockHash() const {
        return *phashBlock;
    }

    int64_t getBlockTime() const {
        return (int64_t)nTime;
    }

    int64_t getBlockTimeMax() const {
        return (int64_t)nTimeMax;
    }

    enum { nMedianTimeSpan=11 };

    int64_t getMedianTimePast() const {
        int64_t pmedian[nMedianTimeSpan];
        int64_t* pbegin = &pmedian[nMedianTimeSpan];
        int64_t* pend = &pmedian[nMedianTimeSpan];

        const BLBlockIndex* pidx = this;
        for (int i = 0; i < nMedianTimeSpan && pidx; i++, pidx = pidx->pprev)
            *(--pbegin) = pidx->getBlockTime();

        std::sort(pbegin, pend);
        return pbegin[(pend - pbegin)/2];
    }

    std::string ToString() const {
        return strprintf("BLBlockIndex(pprev=%p, nHeight=%d, merkle=%s, hashBlock=%s)",
            pprev, nHeight,
            hashMerkleRoot.ToString(),
            getBlockHash().ToString());
    }

    //! Check whether this block index entry is valid up to the passed validity level.
    bool IsValid(enum BlockStatus nUpTo = BLOCK_VALID_TRANSACTIONS) const {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        return ((nStatus & BLOCK_VALID_MASK) >= nUpTo);
    }

    //! Raise the validity level of this block index entry.
    //! Returns true if the validity was changed.
    bool RaiseValidity(enum BlockStatus nUpTo) {
        assert(!(nUpTo & ~BLOCK_VALID_MASK)); // Only validity flags allowed.
        if (nStatus & BLOCK_FAILED_MASK)
            return false;
        if ((nStatus & BLOCK_VALID_MASK) < nUpTo) {
            nStatus = (nStatus & ~BLOCK_VALID_MASK) | nUpTo;
            return true;
        } return false;
    }

    //! Build the skiplist pointer for this entry.
    void BuildSkip();

    //! Efficiently find an ancestor of this block.
    BLBlockIndex* getAncestor(int height);
    const BLBlockIndex* getAncestor(int height) const;
};

arith_uint256 getBlockProof(const BLBlockIndex& block);
/** Return the time it would take to redo the work difference between from and to, assuming the current hashrate corresponds to the difficulty at tip, in seconds. */
int64_t getBlockProofEquivalentTime(const BLBlockIndex& to, const BLBlockIndex& from, const BLBlockIndex& tip, const Consensus::Params&);
/** find the forking point between two chain tips. */
const BLBlockIndex* LastCommonAncestor(const BLBlockIndex* pa, const BLBlockIndex* pb);


/** Used to marshal pointers into hashes for db storage. */
class CDiskBlockIndex : public BLBlockIndex {
public:
    uint256 hashPrev;

    CDiskBlockIndex() {
        hashPrev = uint256();
    }

    explicit CDiskBlockIndex(const BLBlockIndex* pidx) : BLBlockIndex(*pidx) {
        hashPrev = (pprev ? pprev->getBlockHash() : uint256());
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int _nVersion = s.getVersion();
        if (!(s.getType() & SER_GETHASH))
            READWRITE(VARINT(_nVersion));

        READWRITE(VARINT(nHeight));
        READWRITE(VARINT(nStatus));
        READWRITE(VARINT(nTx));
        if (nStatus & (BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO))
            READWRITE(VARINT(nFile));
        if (nStatus & BLOCK_HAVE_DATA)
            READWRITE(VARINT(nDataPos));
        if (nStatus & BLOCK_HAVE_UNDO)
            READWRITE(VARINT(nUndoPos));

        // block header
        READWRITE(this->nVersion);
        READWRITE(hashPrev);
        READWRITE(hashMerkleRoot);
        for(size_t i = 0; i < (sizeof(nReserved) / sizeof(nReserved[0])); i++) {
            READWRITE(nReserved[i]);
        } READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(nSolution);
    }

    uint256 getBlockHash() const {
        BLBlockHeader block;
        block.nVersion        = nVersion;
        block.hashPrevBlock   = hashPrev;
        block.hashMerkleRoot  = hashMerkleRoot;
        block.nHeight         = nHeight;
        memcpy(block.nReserved, nReserved, sizeof(block.nReserved));
        block.nTime           = nTime;
        block.nBits           = nBits;
        block.nNonce          = nNonce;
        block.nSolution       = nSolution;
        return block.getHash();
    }


    std::string ToString() const {
        std::string str = "CDiskBlockIndex(";
        str += BLBlockIndex::ToString();
        str += strprintf("\n                hashBlock=%s, hashPrev=%s)",
            getBlockHash().ToString(),
            hashPrev.ToString());
        return str;
    }
};

/** An in-memory indexed chain of blocks. */
class WBLChain {
private:
    std::vector<BLBlockIndex*> wblChain;

public:
    /** Returns the index entry for the genesis block of this chain, or nullptr if none. */
    BLBlockIndex *Genesis() const {
        return wblChain.size() > 0 ? wblChain[0] : nullptr;
    }

    /** Returns the index entry for the tip of this chain, or nullptr if none. */
    BLBlockIndex *Tip() const {
        return wblChain.size() > 0 ? wblChain[wblChain.size() - 1] : nullptr;
    }

    /** Returns the index entry at a particular height in this chain, or nullptr if no such height exists. */
    BLBlockIndex *operator[](int nHeight) const {
        if (nHeight < 0 || nHeight >= (int)wblChain.size())
            return nullptr;
        return wblChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const WBLChain &a, const WBLChain &b) {
        return a.wblChain.size() == b.wblChain.size() &&
               a.wblChain[a.wblChain.size() - 1] == b.wblChain[b.wblChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const BLBlockIndex *pidx) const {
        return (*this)[pidx->nHeight] == pidx;
    }

    /** find the successor of a block in this chain, or nullptr if the given index is not found or is the tip. */
    BLBlockIndex *Next(const BLBlockIndex *pidx) const {
        if (Contains(pidx))
            return (*this)[pidx->nHeight + 1];
        else
            return nullptr;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const {
        return wblChain.size() - 1;
    }

    /** set/initialize a chain with a given tip. */
    void setInfo(BLBlockIndex *pidx);

    /** Return a BLBlockLocator that refers to a block in this chain (by default the tip). */
    BLBlockLocator getLocator(const BLBlockIndex *pidx = nullptr) const;

    /** find the last common block between this chain and a block index entry. */
    const BLBlockIndex *findFork(const BLBlockIndex *pidx) const;

    /** find the earliest block with timestamp equal or greater than the given. */
    BLBlockIndex* findEarliestAtLeast(int64_t nTime) const;
};

#endif // WIZBL_CHAIN_H
