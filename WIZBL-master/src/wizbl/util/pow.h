// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WIZBL_POW_H
#define WIZBL_POW_H

#include "wizbl/blockchain/util/arith_uint256.h"
#include "wizbl/blockchain/consensus/params.h"

#include <stdint.h>

class BLBlockHeader;
class BLBlockIndex;
class WBLChainParams;
class uint256;

unsigned int getNextWorkRequired(const BLBlockIndex* pidxLast, const BLBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(arith_uint256 bnAvg, int64_t nLastBlockTime, int64_t nFirstBlockTime, const Consensus::Params& params);

unsigned int WizblgetNextWorkRequired(const BLBlockIndex* pidxLast, const BLBlockHeader *pblock, const Consensus::Params& params);
unsigned int WizblCalculateNextWorkRequired(const BLBlockIndex* pidxLast, int64_t nFirstBlockTime, const Consensus::Params& params);

/** Check whether the Equihash solution in a block header is valid */
bool CheckEquihashSolution(const BLBlockHeader *pblock, const WBLChainParams&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, bool postfork, const Consensus::Params&);

#endif // WIZBL_POW_H
