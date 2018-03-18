// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "wizbl/blockchain/util/arith_uint256.h"
#include "wizbl/blockchain/chain.h"
#include "wizbl/blockchain/chainparams.h"
#include "wizbl/blockchain/crypto/equihash.h"
#include "wizbl/blockchain/primitives/block.h"
#include "wizbl/util/streams.h"
#include "wizbl/blockchain/util/uint256.h"
#include "wizbl/blockchain/util/util.h"

unsigned int getNextWorkRequired(const BLBlockIndex* pidxLast, const BLBlockHeader *pblock, const Consensus::Params& params) {
    assert(pidxLast != nullptr);
    int nHeight = pidxLast->nHeight + 1;
    bool postfork = nHeight >= params.BLHeight;
    unsigned int nProofOfWorkLimit = UintToArith256(params.PowLimit(postfork)).getCompact();

    if (postfork == false) {
        return WizblgetNextWorkRequired(pidxLast, pblock, params);
    }
    else if (nHeight < params.BLHeight + params.BLPremineWindow) {
        return nProofOfWorkLimit;
    }
    else if (nHeight < params.BLHeight + params.BLPremineWindow + params.nPowAveragingWindow){
        return UintToArith256(params.powLimitStart).getCompact();
    }
    
    const BLBlockIndex* pidxFirst = pidxLast;
    arith_uint256 bnTot {0};
    for (int i = 0; pidxFirst && i < params.nPowAveragingWindow; i++) {
        arith_uint256 bnTmp;
        bnTmp.setCompact(pidxFirst->nBits);
        bnTot += bnTmp;
        pidxFirst = pidxFirst->pprev;
    }
    
    if (pidxFirst == NULL)
        return nProofOfWorkLimit;
    
    arith_uint256 bnAvg {bnTot / params.nPowAveragingWindow};
    

    return CalculateNextWorkRequired(bnAvg, pidxLast->getMedianTimePast(), pidxFirst->getMedianTimePast(), params);
}

unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg, int64_t nLastBlockTime, int64_t nFirstBlockTime, const Consensus::Params& params) {
    
    // Limit adjustment
    int64_t nActualTimespan = nLastBlockTime - nFirstBlockTime;
    
    if (nActualTimespan < params.MinActualTimespan())
        nActualTimespan = params.MinActualTimespan();
    if (nActualTimespan > params.MaxActualTimespan())
        nActualTimespan = params.MaxActualTimespan();

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.PowLimit(true));
    arith_uint256 bnNew {bnAvg};
    bnNew /= params.AveragingWindowTimespan();
    bnNew *= nActualTimespan;
    
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.getCompact();
}


// Deprecated for Wizbl
unsigned int WizblgetNextWorkRequired(const BLBlockIndex* pidxLast, const BLBlockHeader *pblock, const Consensus::Params& params) {
    assert(pidxLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.PowLimit(false)).getCompact();
    
    // Only change once per difficulty adjustment interval
    if ((pidxLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->getBlockTime() > pidxLast->getBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else {
                // Return the last non-special-min-difficulty-rules-block
                const BLBlockIndex* pidx = pidxLast;
                while (pidx->pprev && pidx->nHeight % params.DifficultyAdjustmentInterval() != 0 && pidx->nBits == nProofOfWorkLimit)
                    pidx = pidx->pprev;
                return pidx->nBits;
            } } return pidxLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pidxLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const BLBlockIndex* pidxFirst = pidxLast->getAncestor(nHeightFirst);
    assert(pidxFirst);

    return WizblCalculateNextWorkRequired(pidxLast, pidxFirst->getBlockTime(), params);
}


// Depricated for Wizbl
unsigned int WizblCalculateNextWorkRequired(const BLBlockIndex* pidxLast, int64_t nFirstBlockTime, const Consensus::Params& params) {
    if (params.fPowNoRetargeting)
        return pidxLast->nBits;
    
    // Limit adjustment step
    int64_t nActualTimespan = pidxLast->getBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespanLegacy/4)
        nActualTimespan = params.nPowTargetTimespanLegacy/4;
    if (nActualTimespan > params.nPowTargetTimespanLegacy*4)
        nActualTimespan = params.nPowTargetTimespanLegacy*4;
    
    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.PowLimit(false));
    arith_uint256 bnNew;
    bnNew.setCompact(pidxLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespanLegacy;
    
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;
    
    return bnNew.getCompact();
}

bool CheckEquihashSolution(const BLBlockHeader *pblock, const WBLChainParams& params) {
    unsigned int n = params.EquihashN();
    unsigned int k = params.EquihashK();

    // Hash state
    crypto_generichash_blake2b_state state;
    EhInitialiseState(n, k, state);

    // I = the block header minus nonce and solution.
    CEquihashInput I{*pblock};
    // I||V
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << I;
    ss << pblock->nNonce;

    // H(I||V||...
    crypto_generichash_blake2b_update(&state, (unsigned char*)&ss[0], ss.size());

    bool isValid;
    EhIsValidSolution(n, k, state, pblock->nSolution, isValid);
    if (!isValid)
        return error("CheckEquihashSolution(): invalid solution");

    return true;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, bool postfork, const Consensus::Params& params) {
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.setCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.PowLimit(postfork)))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
