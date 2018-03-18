// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wizbl/blockchain/chain.h"

BLBlockLocator WBLChain::getLocator(const BLBlockIndex *pidx) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pidx)
        pidx = Tip();
    while (pidx) {
        vHave.push_back(pidx->getBlockHash());
        // Stop when we have added the genesis block.
        if (pidx->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pidx->nHeight - nStep, 0);
        if (Contains(pidx)) {
            // Use O(1) WBLChain index if possible.
            pidx = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pidx = pidx->getAncestor(nHeight);
        } if (vHave.size() > 10)
            nStep *= 2;
    }

    return BLBlockLocator(vHave);
}

void WBLChain::setTip(BLBlockIndex *pidx) {
    if (pidx == nullptr) {
        wblChain.clear();
        return;
    }
    wblChain.resize(pidx->nHeight + 1);
    while (pidx && wblChain[pidx->nHeight] != pidx) {
        wblChain[pidx->nHeight] = pidx;
        pidx = pidx->pprev;
    }
}

const BLBlockIndex *WBLChain::findFork(const BLBlockIndex *pidx) const {
    if (pidx == nullptr) {
        return nullptr;
    }
    if (pidx->nHeight > Height())
        pidx = pidx->getAncestor(Height());
    while (pidx && !Contains(pidx))
        pidx = pidx->pprev;
    return pidx;
}

BLBlockIndex* WBLChain::findEarliestAtLeast(int64_t nTime) const {
    std::vector<BLBlockIndex*>::const_iterator lower = std::lower_bound(wblChain.begin(), wblChain.end(), nTime,
        [](BLBlockIndex* pBlock, const int64_t& time) -> bool { return pBlock->getBlockTimeMax() < time; });
    return (lower == wblChain.end() ? nullptr : *lower);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the BLBlockIndex::pskip pointer. */
int static inline getSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

BLBlockIndex* BLBlockIndex::getAncestor(int height) {
    if (height > nHeight || height < 0)
        return nullptr;

    BLBlockIndex* pidxWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = getSkipHeight(heightWalk);
        int heightSkipPrev = getSkipHeight(heightWalk - 1);
        if (pidxWalk->pskip != nullptr &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pidxWalk = pidxWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pidxWalk->pprev);
            pidxWalk = pidxWalk->pprev;
            heightWalk--;
        }
    }
    return pidxWalk;
}

const BLBlockIndex* BLBlockIndex::getAncestor(int height) const {
    return const_cast<BLBlockIndex*>(this)->getAncestor(height);
}

void BLBlockIndex::BuildSkip() {
    if (pprev)
        pskip = pprev->getAncestor(getSkipHeight(nHeight));
}

arith_uint256 getBlockProof(const BLBlockIndex& block) {
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.setCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t getBlockProofEquivalentTime(const BLBlockIndex& to, const BLBlockIndex& from, const BLBlockIndex& tip, const Consensus::Params& params) {
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / getBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.getLow64();
}

/** find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
const BLBlockIndex* LastCommonAncestor(const BLBlockIndex* pa, const BLBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->getAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->getAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}
