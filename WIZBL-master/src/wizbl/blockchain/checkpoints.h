// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WIZBL_CHECKPOINTS_H
#define WIZBL_CHECKPOINTS_H

#include "wizbl/blockchain/util/uint256.h"

#include <map>

class BLBlockIndex;
struct CCheckpointData;

/**
 * Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints {

//! Returns last BLBlockIndex* in mapBlockIndex that is a checkpoint
BLBlockIndex* getLastCheckpoint(const CCheckpointData& data);

} //namespace Checkpoints

#endif // WIZBL_CHECKPOINTS_H
