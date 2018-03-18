// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "wizbl/blockchain/chain.h"
#include "wizbl/blockchain/chainparams.h"
#include "reverse_iterator.h"
#include "wizbl/util/validation/validation.h"
#include "wizbl/blockchain/util/uint256.h"

#include <stdint.h>


namespace Checkpoints {

    BLBlockIndex* getLastCheckpoint(const CCheckpointData& data) {
        const MapCheckpoints& checkpoints = data.mapCheckpoints;

        for (const MapCheckpoints::value_type& i : reverse_iterate(checkpoints)) {
            const uint256& hash = i.second;
            BlockMap::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        } return nullptr;
    }

} // namespace Checkpoints
