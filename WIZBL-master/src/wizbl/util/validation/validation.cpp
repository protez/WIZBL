// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wizbl/util/validation/validation.h"

#include "wizbl/blockchain/util/arith_uint256.h"
#include "wizbl/blockchain/chain.h"
#include "wizbl/blockchain/chainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "wizbl/blockchain/consensus/consensus.h"
#include "wizbl/blockchain/consensus/merkle.h"
#include "wizbl/blockchain/consensus/tx_verify.h"
#include "wizbl/blockchain/consensus/validation.h"
#include "cuckoocache.h"
#include "fs.h"
#include "wizbl/util/hash.h"
#include "init.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "policy/rbf.h"
#include "pow.h"
#include "wizbl/blockchain/primitives/block.h"
#include "wizbl/blockchain/primitives/transaction.h"
#include "wizbl/util/random.h"
#include "reverse_iterator.h"
#include "script/script.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "wizbl/util/timedata.h"
#include "wizbl/blockchain/util/tinyformat.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "undo.h"
#include "wizbl/blockchain/util/util.h"
#include "wizbl/blockchain/util/utilmoneystr.h"
#include "wizbl/blockchain/util/utilstrencodings.h"
#include "wizbl/util/validation/validationinterface.h"
#include "wizbl/blockchain/versionbits.h"
#include "warnings.h"

#include <atomic>
#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/thread.hpp>

#if defined(NDEBUG)
# error "Wizbl cannot be compiled without assertions."
#endif

/**
 * Global state
 */

BLCriticalSection cs_main;

BlockMap mapBlockIndex;
WBLChain chainActive;
BLBlockIndex *pidxBestHeader = nullptr;
CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;
int nScriptCheckThreads = 0;
std::atomic_bool fImporting(false);
bool fReindex = false;
bool fTxIndex = false;
bool fHavePruned = false;
bool fPruneMode = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;

uint256 hashAssumeValid;

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;

BLBlockPolicyEstimator feeEstimator;
CTxMemPool mempool(&feeEstimator);

static void CheckBlockIndex(const Consensus::Params& consensusParams);

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const std::string strMessageMagic = "Wizbl Signed Message:\n";

// Internal stuff
namespace {

    struct BLBlockIndexWorkComparator {
        bool operator()(const BLBlockIndex *pa, const BLBlockIndex *pb) const {
            // First sort by most total work, ...
            if (pa->nChainWork > pb->nChainWork) return false;
            if (pa->nChainWork < pb->nChainWork) return true;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with blocks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical blocks.
            return false;
        }
    };

    BLBlockIndex *pidxBestInvalid;

    /**
     * The set of all BLBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the block.
     */
    std::set<BLBlockIndex*, BLBlockIndexWorkComparator> setBlockIndexCandidates;
    /** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     * Pruned nodes may have entries where B is missing data.
     */
    std::multimap<BLBlockIndex*, BLBlockIndex*> mapBlocksUnlinked;

    BLCriticalSection cs_LastBlockFile;
    std::vector<BLBlockFileInfo> vinfoBlockFile;
    int nLastBlockFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    BLCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    int32_t nBlockSequenceId = 1;
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;
    /** chainwork for the last block that preciousblock has been applied to. */
    arith_uint256 nLastPreciousChainwork = 0;

    /** Dirty block index entries. */
    std::set<BLBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    std::set<int> setDirtyFileInfo;
} // anon namespace

BLBlockIndex* findForkInGlobalIndex(const WBLChain& chain, const BLBlockLocator& locator) {
    // find the first block the caller has in the main chain
    for (const uint256& hash : locator.vHave) {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            BLBlockIndex* pidx = (*mi).second;
            if (chain.Contains(pidx))
                return pidx;
            if (pidx->getAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            } }
    }
    return chain.Genesis();
}

CCoinsViewDB *pcoinsdbview = nullptr;
CCoinsViewCache *pcoinsTip = nullptr;
BLBlockTreeDB *pblocktree = nullptr;

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

// See definition for documentation
static bool FlushStateToDisk(const WBLChainParams& chainParams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight=0);
static void findFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);
static void findFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks = nullptr);
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);

bool CheckFinalTx(const CTransaction &tx, int flags) {
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // BLBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? chainActive.Tip()->getMedianTimePast()
                             : getAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool TestLockPointValidity(const LockPoints* lp) {
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp, bool useExistingLockPoints) {
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    BLBlockIndex* tip = chainActive.Tip();
    BLBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip, mempool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.getCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }     if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            } } lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }     }     lp->maxInputBlock = tip->getAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
static unsigned int getBlockScriptFlags(const BLBlockIndex* pidx, const Consensus::Params& chainparams);

static void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age) {
    int expired = pool.Expire(getTime() - age);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state) {
    return strprintf("%s%s (code %i)",
        state.getRejectReason(),
        state.getDebugMessage().empty() ? "" : ", "+state.getDebugMessage(),
        state.getRejectCode());
}

static bool IsCurrentForFeeEstimation() {
    AssertLockHeld(cs_main);
    if (IsInitialBlockDownload())
        return false;
    if (chainActive.Tip()->getBlockTime() < (getTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (chainActive.Height() < pidxBestHeader->nHeight - 1)
        return false;
    return true;
}

bool static IsBLHardForkEnabled(int nHeight, const Consensus::Params& params) {
    return nHeight >= params.BLHeight;
}

bool IsBLHardForkEnabled(const BLBlockIndex* pidxPrev, const Consensus::Params& params) {
    if (pidxPrev == nullptr) {
        return false;
    }

    return IsBLHardForkEnabled(pidxPrev->nHeight, params);
}

bool IsBLHardForkEnabledForCurrentBlock(const Consensus::Params& params) {
    AssertLockHeld(cs_main);
    return IsBLHardForkEnabled(chainActive.Tip(), params);
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

void UpdateMempoolForReorg(DisconnectedBlockTransactions &disconnectpool, bool fAddToMempool) {
    AssertLockHeld(cs_main);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() || !AcceptToMemoryPool(mempool, stateDummy, *it, false, nullptr, nullptr, true)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->getHash())) {
            vHashUpdate.push_back((*it)->getHash());
        } ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(pcoinsTip, chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, gArgs.getArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.getArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
}

// Used to avoid mempool polluting consensus critical paths if CCoinsViewMempool
// were somehow broken and returning the wrong scriptPubKeys
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &view, CTxMemPool& pool,
                 unsigned int flags, bool cacheSigStore, PrecomputedTransactionData& txdata) {
    AssertLockHeld(cs_main);

    // pool.cs should be locked already, but go ahead and re-take the lock here
    // to enforce that mempool doesn't change between when we check the view
    // and when we actually call through to CheckInputs
    LOCK(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // At this point we haven't actually checked if the coins are all
        // available (or shouldn't assume we have, since CheckInputs does).
        // So we just return failure if the inputs are not available here,
        // and then only have to check equivalence for available inputs.
        if (coin.IsSpent()) return false;

        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->getHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromDisk = pcoinsTip->AccessCoin(txin.prevout);
            assert(!coinFromDisk.IsSpent());
            assert(coinFromDisk.out == coin.out);
        }
    }

    return CheckInputs(tx, state, view, true, flags, cacheSigStore, true, txdata);
}

static bool AcceptToMemoryPoolWorker(const WBLChainParams& chainparams, CTxMemPool& pool, CValidationState& state, const CTransactionRef& ptx, bool fLimitFree,
                              bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                              bool fOverrideMempoolLimit, const CAmount& nAbsurdFee, std::vector<COutPoint>& coins_to_uncache) {
    const CTransaction& tx = *ptx;
    const uint256 hash = tx.getHash();
    AssertLockHeld(cs_main);
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Reject transactions with witness before segregated witness activates (override with -prematurewitness)
    bool witnessEnabled = IsWitnessEnabled(chainActive.Tip(), chainparams.getConsensus());
    if (!gArgs.getBoolArg("-prematurewitness", false) && tx.HasWitness() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason, witnessEnabled))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash)) {
        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    std::set<uint256> setConflicts; {
    LOCK(pool.cs); // protect pool.mapNextTx
    for (const CTxIn &txin : tx.vin) {
        auto itConflicting = pool.mapNextTx.find(txin.prevout);
        if (itConflicting != pool.mapNextTx.end()) {
            const CTransaction *ptxConflicting = itConflicting->second;
            if (!setConflicts.count(ptxConflicting->getHash())) {
                // Allow opt-out of transaction replacement by setting
                // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
                //
                // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
                // non-replaceable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                if (fEnableReplacement) {
                    for (const CTxIn &_txin : ptxConflicting->vin)
                    {
                        if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE)
                        {
                            fReplacementOptOut = false;
                            break;
                        }             }         }         if (fReplacementOptOut) {
                    return state.Invalid(false, REJECT_DUPLICATE, "txn-mempool-conflict");
                }

                setConflicts.insert(ptxConflicting->getHash());
            } }
    }
    }
 {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        CAmount nValueIn = 0;
        LockPoints lp; {
        LOCK(pool.cs);
        CCoinsViewMemPool viewMemPool(pcoinsTip, pool);
        view.setBackend(viewMemPool);

        // do all inputs exist?
        for (const CTxIn txin : tx.vin) {
            if (!pcoinsTip->HaveCoinInCache(txin.prevout)) {
                coins_to_uncache.push_back(txin.prevout);
            }     if (!view.HaveCoin(txin.prevout)) {
                // Are inputs missing because we already have the tx?
                for (size_t out = 0; out < tx.vout.size(); out++) {
                    // Optimistically just do efficient check of cache for outputs
                    if (pcoinsTip->HaveCoinInCache(COutPoint(hash, out))) {
                        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-known");
                    }         }         // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
                if (pfMissingInputs) {
                    *pfMissingInputs = true;
                }         return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
            } }

        // Bring the best block into scope
        view.getBestBlock();

        nValueIn = view.getValueIn(tx);

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.setBackend(dummy);

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // block; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
        // CoinsViewCache instead of create its own
        if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        // Check for non-standard witness in P2WSH
        if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, view))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-witness-nonstandard", true);

        int64_t nSigOpsCost = getTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);

        CAmount nValueOut = tx.getValueOut();
        CAmount nFees = nValueIn-nValueOut;
        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        pool.ApplyDelta(hash, nModifiedFees);

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        for (const CTxIn &txin : tx.vin) {
            const Coin &coin = view.AccessCoin(txin.prevout);
            if (coin.IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            } }

        CTxMemPoolEntry entry(ptx, nFees, nAcceptTime, chainActive.Height(),
                              fSpendsCoinbase, nSigOpsCost, lp);
        unsigned int nSize = entry.getTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d", nSigOpsCost));

        CAmount mempoolRejectFee = pool.getMinFee(gArgs.getArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).getFee(nSize);
        if (mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false, strprintf("%d < %d", nFees, mempoolRejectFee));
        }

        // No transactions are allowed below minRelayTxFee except from disconnected blocks
        if (fLimitFree && nModifiedFees < ::minRelayTxFee.getFee(nSize)) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "min relay fee not met");
        }

        if (nAbsurdFee && nFees > nAbsurdFee)
            return state.Invalid(false,
                REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));

        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.getArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.getArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = gArgs.getArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.getArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
        }

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure setConflicts and setAncestors don't
        // intersect.
        for (CTxMemPool::txiter ancestorIt : setAncestors) {
            const uint256 &hashAncestor = ancestorIt->getTx().getHash();
            if (setConflicts.count(hashAncestor)) {
                return state.DoS(10, false,
                                 REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                                 strprintf("%s spends conflicting transaction %s",
                                           hash.ToString(),
                                           hashAncestor.ToString()));
            } }

        // Check if it's economically rational to mine this transaction rather
        // than the ones it replaces.
        CAmount nConflictingFees = 0;
        size_t nConflictingSize = 0;
        uint64_t nConflictingCount = 0;
        CTxMemPool::setEntries allConflicting;

        // If we don't hold the lock allConflicting might be incomplete; the
        // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
        // mempool consistency for us.
        LOCK(pool.cs);
        const bool fReplacementTransaction = setConflicts.size();
        if (fReplacementTransaction) {
            CFeeRate newFeeRate(nModifiedFees, nSize);
            std::set<uint256> setConflictsParents;
            const int maxDescendantsToVisit = 100;
            CTxMemPool::setEntries setIterConflicting;
            for (const uint256 &hashConflicting : setConflicts) {
                CTxMemPool::txiter mi = pool.mapTx.find(hashConflicting);
                if (mi == pool.mapTx.end())
                    continue;

                // Save these to avoid repeated lookups
                setIterConflicting.insert(mi);

                // Don't allow the replacement to reduce the feerate of the
                // mempool.
                //
                // We usually don't want to accept replacements with lower
                // feerates than what they replaced as that would lower the
                // feerate of the next block. Requiring that the feerate always
                // be increased is also an easy-to-reason about way to prevent
                // DoS attacks via replacements.
                //
                // The mining code doesn't (currently) take children into
                // account (CPFP) so we only consider the feerates of
                // transactions being directly replaced, not their indirect
                // descendants. While that does mean high feerate children are
                // ignored when deciding whether or not to replace, we do
                // require the replacement to pay more overall fees too,
                // mitigating most cases.
                CFeeRate oldFeeRate(mi->getModifiedFee(), mi->getTxSize());
                if (newFeeRate <= oldFeeRate) {
                    return state.DoS(0, false,
                            REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                            strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                                  hash.ToString(),
                                  newFeeRate.ToString(),
                                  oldFeeRate.ToString()));
                }

                for (const CTxIn &txin : mi->getTx().vin) {
                    setConflictsParents.insert(txin.prevout.hash);
                }

                nConflictingCount += mi->getCountWithDescendants();
            }     // This potentially overestimates the number of actual descendants
            // but we just want to be conservative to avoid doing too much
            // work.
            if (nConflictingCount <= maxDescendantsToVisit) {
                // If not too many to replace, then calculate the set of
                // transactions that would have to be evicted
                for (CTxMemPool::txiter it : setIterConflicting) {
                    pool.CalculateDescendants(it, allConflicting);
                }         for (CTxMemPool::txiter it : allConflicting) {
                    nConflictingFees += it->getModifiedFee();
                    nConflictingSize += it->getTxSize();
                }     } else {
                return state.DoS(0, false,
                        REJECT_NONSTANDARD, "too many potential replacements", false,
                        strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                            hash.ToString(),
                            nConflictingCount,
                            maxDescendantsToVisit));
            }

            for (unsigned int j = 0; j < tx.vin.size(); j++) {
                // We don't want to accept replacements that require low
                // feerate junk to be mined first. Ideally we'd keep track of
                // the ancestor feerates and make the decision based on that,
                // but for now requiring all new inputs to be confirmed works.
                if (!setConflictsParents.count(tx.vin[j].prevout.hash)) {
                    // Rather than check the UTXO set - potentially expensive -
                    // it's cheaper to just check if the new input refers to a
                    // tx that's in the mempool.
                    if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
                        return state.DoS(0, false,
                                         REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                                         strprintf("replacement %s adds unconfirmed input, idx %d",
                                                  hash.ToString(), j));
                }     }

            // The replacement must pay greater fees than the transactions it
            // replaces - if we did the bandwidth used by those conflicting
            // transactions would not be paid for.
            if (nModifiedFees < nConflictingFees) {
                return state.DoS(0, false,
                                 REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                 strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                                          hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
            }

            // Finally in addition to paying more fees than the conflicts the
            // new transaction must pay for its own bandwidth.
            CAmount nDeltaFees = nModifiedFees - nConflictingFees;
            if (nDeltaFees < ::incrementalRelayFee.getFee(nSize)) {
                return state.DoS(0, false,
                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                        strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                              hash.ToString(),
                              FormatMoney(nDeltaFees),
                              FormatMoney(::incrementalRelayFee.getFee(nSize))));
            } }

        unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (!chainparams.RequireStandard()) {
            scriptVerifyFlags = gArgs.getArg("-promiscuousmempoolflags", scriptVerifyFlags);
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        PrecomputedTransactionData txdata(tx);
        if (!CheckInputs(tx, state, view, true, scriptVerifyFlags, true, false, txdata)) {
            // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
            // need to turn both off, and compare against just turning off CLEANSTACK
            // to see if the failure is specifically due to witness validation.
            CValidationState stateDummy; // Want reported failures to be from first CheckInputs
            if (!tx.HasWitness() && CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, txdata) &&
                !CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, txdata)) {
                // Only the witness is missing, so the transaction itself may be fine.
                state.setCorruptionPossible();
            }     return false; // state filled in by CheckInputs
        }

        // Check again against the current block tip's script verification
        // flags to cache our script execution flags. This is, of course,
        // useless if the next block has different script flags from the
        // previous one, but because the cache tracks script flags for us it
        // will auto-invalidate and we'll just have a few blocks of extra
        // misses on soft-fork activation.
        //
        // This is also useful in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks (using TestBlockValidity), however allowing such
        // transactions into the mempool can be exploited as a DoS attack.
        unsigned int currentBlockScriptVerifyFlags = getBlockScriptFlags(chainActive.Tip(), Params().getConsensus());
        if (!CheckInputsFromMempoolAndCache(tx, state, view, pool, currentBlockScriptVerifyFlags, true, txdata)) {
            // If we're using promiscuousmempoolflags, we may hit this normally
            // Check if current block has some flags that scriptVerifyFlags
            // does not before printing an ominous warning
            if (!(~scriptVerifyFlags & currentBlockScriptVerifyFlags)) {
                return error("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against latest-block but not STANDARD flags %s, %s",
                    __func__, hash.ToString(), FormatStateMessage(state));
            } else {
                if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, false, txdata)) {
                    return error("%s: ConnectInputs failed against MANDATORY but not STANDARD flags due to promiscuous mempool %s, %s",
                        __func__, hash.ToString(), FormatStateMessage(state));
                } else {
                    LogPrintf("Warning: -promiscuousmempool flags set to not include currently enforced soft forks, this may break mining or otherwise cause instability!\n");
                }     } }

        // Remove conflicting transactions from the mempool
        for (const CTxMemPool::txiter it : allConflicting) {
            LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s WIZBL additional fees, %d delta bytes\n",
                    it->getTx().getHash().ToString(),
                    hash.ToString(),
                    FormatMoney(nModifiedFees - nConflictingFees),
                    (int)nSize - (int)nConflictingSize);
            if (plTxnReplaced)
                plTxnReplaced->push_back(it->getSharedTx());
        } pool.RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

        // This transaction should only count for fee estimation if it isn't a
        // BIP 125 replacement transaction (may not be widely supported), the
        // node is not behind, and the transaction is not dependent on any other
        // transactions in the mempool.
        bool validForFeeEstimation = !fReplacementTransaction && IsCurrentForFeeEstimation() && pool.HasNoInputsOf(tx);

        // Store transaction in memory
        pool.addUnchecked(hash, entry, setAncestors, validForFeeEstimation);

        // trim mempool and check if tx was trimmed
        if (!fOverrideMempoolLimit) {
            LimitMempoolSize(pool, gArgs.getArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.getArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }
    }

    getMainSignals().TransactionAddedToMempool(ptx);

    return true;
}

/** (try to) add transaction to memory pool with a specified acceptance time **/
static bool AcceptToMemoryPoolWithTime(const WBLChainParams& chainparams, CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx, bool fLimitFree,
                        bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                        bool fOverrideMempoolLimit, const CAmount nAbsurdFee) {
    std::vector<COutPoint> coins_to_uncache;
    bool res = AcceptToMemoryPoolWorker(chainparams, pool, state, tx, fLimitFree, pfMissingInputs, nAcceptTime, plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee, coins_to_uncache);
    if (!res) {
        for (const COutPoint& hashTx : coins_to_uncache)
            pcoinsTip->Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    CValidationState stateDummy;
    FlushStateToDisk(chainparams, stateDummy, FLUSH_STATE_PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx, bool fLimitFree,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool fOverrideMempoolLimit, const CAmount nAbsurdFee) {
    const WBLChainParams& chainparams = Params();
    return AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, fLimitFree, pfMissingInputs, getTime(), plTxnReplaced, fOverrideMempoolLimit, nAbsurdFee);
}

/** Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock */
bool getTransaction(const uint256 &hash, CTransactionRef &txOut, const Consensus::Params& consensusParams, uint256 &hashBlock, bool fAllowSlow) {
    BLBlockIndex *pidxSlow = nullptr;

    LOCK(cs_main);

    CTransactionRef ptx = mempool.get(hash);
    if (ptx) {
        txOut = ptx;
        return true;
    }

    if (fTxIndex) {
        CDiskTxPos postx;
        if (pblocktree->ReadTxIndex(hash, postx)) {
            CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
            if (file.IsNull())
                return error("%s: OpenBlockFile failed", __func__);
            BLBlockHeader header;
            try {
                file >> header;
                fseek(file.get(), postx.nTxOffset, SEEK_CUR);
                file >> txOut;
            } catch (const std::exception& e) {
                return error("%s: Deserialize or I/O error - %s", __func__, e.what());
            }     hashBlock = header.getHash();
            if (txOut->getHash() != hash)
                return error("%s: txid mismatch", __func__);
            return true;
        }
    }

    if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
        const Coin& coin = AccessByTxid(*pcoinsTip, hash);
        if (!coin.IsSpent()) pidxSlow = chainActive[coin.nHeight];
    }

    if (pidxSlow) {
        BLBlock block;
        if (ReadBlockFromDisk(block, pidxSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->getHash() == hash) {
                    txOut = tx;
                    hashBlock = pidxSlow->getBlockHash();
                    return true;
                }     } }
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// BLBlock and BLBlockIndex
//

static bool WriteBlockToDisk(const BLBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart) {
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = getSerializeSize(fileout, block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(BLBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams) {
    block.setNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check Equihash solution
    bool postfork = block.nHeight >= (uint32_t)consensusParams.BLHeight;
    if (postfork && !CheckEquihashSolution(&block, Params())) {
        return error("ReadBlockFromDisk: Errors in block header at %s (bad Equihash solution)", pos.ToString());
    }
    // Check the header
    if (!CheckProofOfWork(block.getHash(), block.nBits, postfork, consensusParams))
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}

bool ReadBlockFromDisk(BLBlock& block, const BLBlockIndex* pidx, const Consensus::Params& consensusParams) {
    if (!ReadBlockFromDisk(block, pidx->getBlockPos(), consensusParams))
        return false;
    if (block.getHash() != pidx->getBlockHash())
        return error("ReadBlockFromDisk(BLBlock&, BLBlockIndex*): getHash() doesn't match index for %s at %s",
                pidx->ToString(), pidx->getBlockPos().ToString());
    return true;
}

CAmount getBlockSubsidy(int nHeight, const Consensus::Params& consensusParams) {
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    CAmount nSubsidy = 50 * COIN;
    // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}

bool IsInitialBlockDownload() {
    const WBLChainParams& chainParams = Params();

    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (chainActive.Tip() == nullptr)
        return true;
    if (chainActive.Tip()->nChainWork < UintToArith256(chainParams.getConsensus().nMinimumChainWork))
        return true;
    if (chainActive.Tip()->getBlockTime() < (getTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

BLBlockIndex *pidxBestForkTip = nullptr, *pidxBestForkBase = nullptr;

static void AlertNotify(const std::string& strMessage) {
    uiInterface.NotifyAlertChanged();
    std::string strCmd = gArgs.getArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    boost::thread t(runCommand, strCmd); // thread runs free
}

static void CheckForkWarningConditions() {
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pidxBestForkTip && chainActive.Height() - pidxBestForkTip->nHeight >= 72)
        pidxBestForkTip = nullptr;

    if (pidxBestForkTip || (pidxBestInvalid && pidxBestInvalid->nChainWork > chainActive.Tip()->nChainWork + (getBlockProof(*chainActive.Tip()) * 6))) {
        if (!getfLargeWorkForkFound() && pidxBestForkBase) {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                pidxBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        } if (pidxBestForkTip && pidxBestForkBase) {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   pidxBestForkBase->nHeight, pidxBestForkBase->phashBlock->ToString(),
                   pidxBestForkTip->nHeight, pidxBestForkTip->phashBlock->ToString());
            setfLargeWorkForkFound(true);
        } else {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            setfLargeWorkInvalidChainFound(true);
        }
    }
    else {
        setfLargeWorkForkFound(false);
        setfLargeWorkInvalidChainFound(false);
    }
}

static void CheckForkWarningConditionsOnNewFork(BLBlockIndex* pidxNewForkTip) {
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    BLBlockIndex* pfork = pidxNewForkTip;
    BLBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger) {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pidxBestForkTip || pidxNewForkTip->nHeight > pidxBestForkTip->nHeight) &&
            pidxNewForkTip->nChainWork - pfork->nChainWork > (getBlockProof(*pfork) * 7) &&
            chainActive.Height() - pidxNewForkTip->nHeight < 72) {
        pidxBestForkTip = pidxNewForkTip;
        pidxBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(BLBlockIndex* pidxNew) {
    if (!pidxBestInvalid || pidxNew->nChainWork > pidxBestInvalid->nChainWork)
        pidxBestInvalid = pidxNew;

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pidxNew->getBlockHash().ToString(), pidxNew->nHeight,
      log(pidxNew->nChainWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pidxNew->getBlockTime()));
    BLBlockIndex *tip = chainActive.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->getBlockHash().ToString(), chainActive.Height(), log(tip->nChainWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->getBlockTime()));
    CheckForkWarningConditions();
}

void static InvalidBlockFound(BLBlockIndex *pidx, const CValidationState &state) {
    if (!state.CorruptionPossible()) {
        pidx->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(pidx);
        setBlockIndexCandidates.erase(pidx);
        InvalidChainFound(pidx);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight) {
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin) {
            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight) {
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;
    return VerifyScript(scriptSig, scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, amount, cacheStore, *txdata), &error);
}

int getSpendHeight(const CCoinsViewCache& inputs) {
    LOCK(cs_main);
    BLBlockIndex* pidxPrev = mapBlockIndex.find(inputs.getBestBlock())->second;
    return pidxPrev->nHeight + 1;
}


static CuckooCache::cache<uint256, SignatureCacheHasher> scriptExecutionCache;
static uint256 scriptExecutionCacheNonce(getRandHash());

void InitScriptExecutionCache() {
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, gArgs.getArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) / 2), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = scriptExecutionCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu/2 requested for script execution cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, (nMaxCacheSize*2)>>20, nElems);
}

/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks) {
    if (!tx.IsCoinBase()) {
        if (!Consensus::CheckTxInputs(tx, state, inputs, getSpendHeight(inputs)))
            return false;

        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip script verification when connecting blocks under the
        // assumevalid block. Assuming the assumevalid block is valid this
        // is safe because block merkle hashes are still computed and checked,
        // Of course, if an assumed valid block is invalid due to false scriptSigs
        // this optimization would allow an invalid chain to be accepted.
        if (fScriptChecks) {
            // First check if script executions have been cached with the same
            // flags. Note that this assumes that the inputs provided are
            // correct (ie that the transaction hash which is in tx's prevouts
            // properly commits to the scriptPubKey in the inputs view of that
            // transaction).
            uint256 hashCacheEntry;
            // We only use the first 19 bytes of nonce to avoid a second SHA
            // round - giving us 19 + 32 + 4 = 55 bytes (+ 8 + 1 = 64)
            static_assert(55 - sizeof(flags) - 32 >= 128/8, "Want at least 128 bits of nonce for script execution cache");
            CSHA256().Write(scriptExecutionCacheNonce.begin(), 55 - sizeof(flags) - 32).Write(tx.getWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
            AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks
            if (scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
                return true;
            }

            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint &prevout = tx.vin[i].prevout;
                const Coin& coin = inputs.AccessCoin(prevout);
                assert(!coin.IsSpent());

                // We very carefully only pass in things to CScriptCheck which
                // are clearly committed to by tx' witness hash. This provides
                // a sanity check that our caching is not introducing consensus
                // failures through additional data in, eg, the coins being
                // spent being checked as a part of CScriptCheck.
                const CScript& scriptPubKey = coin.out.scriptPubKey;
                const CAmount amount = coin.out.nValue;

                // Verify signature
                CScriptCheck check(scriptPubKey, amount, tx, i, flags, cacheSigStore, &txdata);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(scriptPubKey, amount, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.getScriptError())));
                    }             // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. an invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after soft-fork
                    // super-majority signaling has occurred.
                    return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.getScriptError())));
                }     }

            if (cacheFullScriptStore && !pvChecks) {
                // We executed all of the provided scripts, and were told to
                // cache the result. Do so now.
                scriptExecutionCache.insert(hashCacheEntry);
            } }
    }

    return true;
}

namespace {

bool UndoWriteToDisk(const BLBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart) {
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = getSerializeSize(fileout, blockundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.getHash();

    return true;
}

bool UndoReadFromDisk(BLBlockUndo& blockundo, const CDiskBlockPos& pos, const uint256& hashBlock) {
    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << hashBlock;
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.getHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage="") {
    setMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage="") {
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

} // namespace

enum DisconnectResult {
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out) {
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // The potential_overwrite parameter to AddCoin is only allowed to be false if we know for
    // sure that the coin did not already exist in the cache. As we have queried for that above
    // using HaveCoin, we don't need to guess. When fClean is false, a coin already existed and
    // it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
static DisconnectResult DisconnectBlock(const BLBlock& block, const BLBlockIndex* pidx, CCoinsViewCache& view) {
    bool fClean = true;

    BLBlockUndo blockUndo;
    CDiskBlockPos pos = pidx->getUndoPos();
    if (pos.IsNull()) {
        error("DisconnectBlock(): no undo data available");
        return DISCONNECT_FAILED;
    }
    if (!UndoReadFromDisk(blockUndo, pos, pidx->pprev->getBlockHash())) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.getHash();
        bool is_coinbase = tx.IsCoinBase();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pidx->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase) {
                    fClean = false; // transaction output mismatch
                }     } }

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }     for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;
            }     // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // move best block pointer to prevout block
    view.setBestBlock(pidx->pprev->getBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

void static FlushBlockFile(bool fFinalize = false) {
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

static bool findUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("wizbl-scriptch");
    scriptcheckqueue.Thread();
}

// Protected by cs_main
VersionBitsCache versionbitscache;

int32_t ComputeBlockVersion(const BLBlockIndex* pidxPrev, const Consensus::Params& params) {
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pidxPrev, params, (Consensus::DeploymentPos)i, versionbitscache);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, (Consensus::DeploymentPos)i);
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker {
private:
    int bit;

public:
    WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const BLBlockIndex* pidx, const Consensus::Params& params) const override {
        return ((pidx->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pidx->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pidx->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

static unsigned int getBlockScriptFlags(const BLBlockIndex* pidx, const Consensus::Params& consensusparams) {
    AssertLockHeld(cs_main);

    // BIP16 didn't become active until Apr 1 2012
    int64_t nBIP16SwitchTime = 1333238400;
    bool fStrictPayToScriptHash = (pidx->getBlockTime() >= nBIP16SwitchTime);

    unsigned int flags = fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE;

    // Start enforcing the DERSIG (BIP66) rule
    if (pidx->nHeight >= consensusparams.BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pidx->nHeight >= consensusparams.BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    if (VersionBitsState(pidx->pprev, consensusparams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Start enforcing WITNESS rules using versionbits logic.
    if (IsWitnessEnabled(pidx->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_WITNESS;
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    if (IsBLHardForkEnabled(pidx->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_STRICTENC;
    } else {
        flags |= SCRIPT_ALLOW_NON_FORKID;
    }

    return flags;
}



static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
static bool ConnectBlock(const BLBlock& block, CValidationState& state, BLBlockIndex* pidx,
                  CCoinsViewCache& view, const WBLChainParams& chainparams, bool fJustCheck = false) {
    AssertLockHeld(cs_main);
    assert(pidx);
    // pidx->phashBlock can be null if called by CreateNewBlock/TestBlockValidity
    assert((pidx->phashBlock == nullptr) ||
           (*pidx->phashBlock == block.getHash()));
    int64_t nTimeStart = getTimeMicros();

    // Check it again in case a previous version let a bad block in
    if (!CheckBlock(block, state, chainparams.getConsensus(), !fJustCheck, !fJustCheck))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pidx->pprev == nullptr ? uint256() : pidx->pprev->getBlockHash();
    assert(hashPrevBlock == view.getBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.getHash() == chainparams.getConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.setBestBlock(pidx->getBlockHash());
        return true;
    }

    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = mapBlockIndex.find(hashAssumeValid);
        if (it != mapBlockIndex.end()) {
            if (it->second->getAncestor(pidx->nHeight) == pidx &&
                pidxBestHeader->getAncestor(pidx->nHeight) == pidx &&
                pidxBestHeader->nChainWork >= UintToArith256(chainparams.getConsensus().nMinimumChainWork)) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // The equivalent time check discourages hash power from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (getBlockProofEquivalentTime(*pidxBestHeader, *pidx, *pidxBestHeader, chainparams.getConsensus()) <= 60 * 60 * 24 * 7 * 2);
            } }
    }

    int64_t nTime1 = getTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs]\n", 0.001 * (nTime1 - nTimeStart), nTimeCheck * 0.000001);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pidx->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                          !((pidx->nHeight==91842 && pidx->getBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pidx->nHeight==91880 && pidx->getBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    BLBlockIndex *pidxBIP34height = pidx->pprev->getAncestor(chainparams.getConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pidxBIP34height || !(pidxBIP34height->getBlockHash() == chainparams.getConsensus().BIP34Hash));

    if (fEnforceBIP30) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->getHash(), o))) {
                    return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                                     REJECT_INVALID, "bad-txns-BIP30");
                }     } }
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pidx->pprev, chainparams.getConsensus(), Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // get the script flags for this block
    unsigned int flags = getBlockScriptFlags(pidx, chainparams.getConsensus());

    int64_t nTime2 = getTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeForks * 0.000001);

    BLBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : nullptr);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    CDiskTxPos pos(pidx->getBlockPos(), getSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        if (!tx.IsCoinBase()) {
            if (!view.HaveInputs(tx))
                return state.DoS(100, error("ConnectBlock(): inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pidx)) {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            } }

        // getTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += getTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        txdata.emplace_back(tx);
        if (!tx.IsCoinBase()) {
            nFees += view.getValueIn(tx)-tx.getValueOut();

            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, fCacheResults, txdata[i], nScriptCheckThreads ? &vChecks : nullptr))
                return error("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.getHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        } UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pidx->nHeight);

        vPos.push_back(std::make_pair(tx.getHash(), pos));
        pos.nTxOffset += ::getSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }
    int64_t nTime3 = getTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)block.vtx.size(), 0.001 * (nTime3 - nTime2), 0.001 * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * 0.000001);

    CAmount blockReward = nFees + getBlockSubsidy(pidx->nHeight, chainparams.getConsensus());
    if (block.vtx[0]->getValueOut() > blockReward)
        return state.DoS(100,
                         error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                               block.vtx[0]->getValueOut(), blockReward),
                               REJECT_INVALID, "bad-cb-amount");

    if (!control.Wait())
        return state.DoS(100, error("%s: CheckQueue failed", __func__), REJECT_INVALID, "block-validation-failed");
    int64_t nTime4 = getTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime4 - nTime2), nInputs <= 1 ? 0 : 0.001 * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * 0.000001);

    if (fJustCheck)
        return true;

    // Write undo information to disk
    if (pidx->getUndoPos().IsNull() || !pidx->IsValid(BLOCK_VALID_SCRIPTS)) {
        if (pidx->getUndoPos().IsNull()) {
            CDiskBlockPos _pos;
            if (!findUndoPos(state, pidx->nFile, _pos, ::getSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock(): findUndoPos failed");
            if (!UndoWriteToDisk(blockundo, _pos, pidx->pprev->getBlockHash(), chainparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pidx->nUndoPos = _pos.nPos;
            pidx->nStatus |= BLOCK_HAVE_UNDO;
        }

        pidx->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pidx);
    }

    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return AbortNode(state, "Failed to write transaction index");

    // add this block to the view's block chain
    view.setBestBlock(pidx->getBlockHash());

    int64_t nTime5 = getTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeIndex * 0.000001);

    int64_t nTime6 = getTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint(BCLog::BENCH, "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5), nTimeCallbacks * 0.000001);

    return true;
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool static FlushStateToDisk(const WBLChainParams& chainparams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight) {
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    LOCK(cs_main);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastsetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    bool fDoFullFlush = false;
    int64_t nNow = 0;
    try { {
        LOCK(cs_LastBlockFile);
        if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
            if (nManualPruneHeight > 0) {
                findFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
            } else {
                findFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                fCheckForPruning = false;
            }     if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }     } } nNow = getTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        } if (nLastFlush == 0) {
            nLastFlush = nNow;
        } if (nLastsetChain == 0) {
            nLastsetChain = nNow;
        } int64_t nMempoolSizeMax = gArgs.getArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
        int64_t cacheSize = pcoinsTip->DynamicMemoryUsage();
        int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize > std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024);
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > nTotalSpace;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(0))
                return state.Error("out of disk space");
            // First make sure all block and undo data is flushed to disk.
            FlushBlockFile();
            // Then update all block file information (which may refer to block and undo files). {
                std::vector<std::pair<int, const BLBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }         std::vector<const BLBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<BLBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }         if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Failed to write to block index database");
                }     }     // Finally remove any pruned files
            if (fFlushForPrune)
                UnlinkPrunedFiles(setFilesToPrune);
            nLastWrite = nNow;
        } // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush) {
            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->getCacheSize()))
                return state.Error("out of disk space");
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
        }
    }
    if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastsetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000)) {
        // Update best block in wallet (so we can detect restored wallets).
        getMainSignals().setBestChain(chainActive.getLocator());
        nLastsetChain = nNow;
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk() {
    CValidationState state;
    const WBLChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush() {
    CValidationState state;
    fCheckForPruning = true;
    const WBLChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE);
}

static void DoWarning(const std::string& strWarning) {
    static bool fWarned = false;
    setMiscWarning(strWarning);
    if (!fWarned) {
        AlertNotify(strWarning);
        fWarned = true;
    }
}

/** Update chainActive and related internal data structures. */
void static UpdateTip(BLBlockIndex *pidxNew, const WBLChainParams& chainParams) {
    chainActive.setInfo(pidxNew);

    // New best block
    mempool.AddTransactionsUpdated(1);

    cvBlockChange.notify_all();

    std::vector<std::string> warningMessages;
    if (!IsInitialBlockDownload()) {
        int nUpgraded = 0;
        const BLBlockIndex* pidx = chainActive.Tip();
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.getStateFor(pidx, chainParams.getConsensus(), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
                const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                if (state == THRESHOLD_ACTIVE) {
                    DoWarning(strWarning);
                } else {
                    warningMessages.push_back(strWarning);
                }     } } // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pidx != nullptr; i++) {
            int32_t nExpectedVersion = ComputeBlockVersion(pidx->pprev, chainParams.getConsensus());
            if (pidx->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pidx->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pidx = pidx->pprev;
        } if (nUpgraded > 0)
            warningMessages.push_back(strprintf(_("%d of last 100 blocks have unexpected version"), nUpgraded));
        if (nUpgraded > 100/2) {
            std::string strWarning = _("Warning: Unknown block versions being mined! It's possible unknown rules are in effect");
            // notify getWarnings(), called by Qt and the JSON-RPC code to warn the user:
            DoWarning(strWarning);
        }
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)", __func__,
      chainActive.Tip()->getBlockHash().ToString(), chainActive.Height(), chainActive.Tip()->nVersion,
      log(chainActive.Tip()->nChainWork.getdouble())/log(2.0), (unsigned long)chainActive.Tip()->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->getBlockTime()),
      GuessVerificationProgress(chainParams.TxData(), chainActive.Tip()), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->getCacheSize());
    if (!warningMessages.empty())
        LogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", "));
    LogPrintf("\n");

}

/** Disconnect chainActive's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling UpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool static DisconnectTip(CValidationState& state, const WBLChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool) {
    BLBlockIndex *pidxDelete = chainActive.Tip();
    assert(pidxDelete);
    // Read block from disk.
    std::shared_ptr<BLBlock> pblock = std::make_shared<BLBlock>();
    BLBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pidxDelete, chainparams.getConsensus()))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = getTimeMicros(); {
        CCoinsViewCache view(pcoinsTip);
        assert(view.getBestBlock() == pidxDelete->getBlockHash());
        if (DisconnectBlock(block, pidxDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pidxDelete->getBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (getTimeMicros() - nStart) * 0.001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_IF_NEEDED))
        return false;

    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        } while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    // Update chainActive and related variables.
    UpdateTip(pidxDelete->pprev, chainparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    getMainSignals().BlockDisconnected(pblock);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    BLBlockIndex* pidx = nullptr;
    std::shared_ptr<const BLBlock> pblock;
    std::shared_ptr<std::vector<CTransactionRef>> conflictedTxs;
    PerBlockConnectTrace() : conflictedTxs(std::make_shared<std::vector<CTransactionRef>>()) {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class also tracks transactions that are removed from the mempool as
 * conflicts (per block) and can be used to pass all those transactions
 * through SyncTransaction.
 *
 * This class assumes (and asserts) that the conflicted transactions for a given
 * block are added via mempool callbacks prior to the BlockConnected() associated
 * with those transactions. If any transactions are marked conflicted, it is
 * assumed that an associated block will always be added.
 *
 * This class is single-use, once you call getBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;
    CTxMemPool &pool;

public:
    ConnectTrace(CTxMemPool &_pool) : blocksConnected(1), pool(_pool) {
        pool.NotifyEntryRemoved.connect(boost::bind(&ConnectTrace::NotifyEntryRemoved, this, _1, _2));
    }

    ~ConnectTrace() {
        pool.NotifyEntryRemoved.disconnect(boost::bind(&ConnectTrace::NotifyEntryRemoved, this, _1, _2));
    }

    void BlockConnected(BLBlockIndex* pidx, std::shared_ptr<const BLBlock> pblock) {
        assert(!blocksConnected.back().pidx);
        assert(pidx);
        assert(pblock);
        blocksConnected.back().pidx = pidx;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& getBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pidx);
        assert(blocksConnected.back().conflictedTxs->empty());
        blocksConnected.pop_back();
        return blocksConnected;
    }

    void NotifyEntryRemoved(CTransactionRef txRemoved, MemPoolRemovalReason reason) {
        assert(!blocksConnected.back().pidx);
        if (reason == MemPoolRemovalReason::CONFLICT) {
            blocksConnected.back().conflictedTxs->emplace_back(std::move(txRemoved));
        }
    }
};

/**
 * Connect a new block to chainActive. pblock is either nullptr or a pointer to a BLBlock
 * corresponding to pidxNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool static ConnectTip(CValidationState& state, const WBLChainParams& chainparams, BLBlockIndex* pidxNew, const std::shared_ptr<const BLBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool) {
    assert(pidxNew->pprev == chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = getTimeMicros();
    std::shared_ptr<const BLBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<BLBlock> pblockNew = std::make_shared<BLBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pidxNew, chainparams.getConsensus()))
            return AbortNode(state, "Failed to read block");
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const BLBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = getTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001); {
        CCoinsViewCache view(pcoinsTip);
        bool rv = ConnectBlock(blockConnecting, state, pidxNew, view, chainparams);
        getMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pidxNew, state);
            return error("ConnectTip(): ConnectBlock %s failed", pidxNew->getBlockHash().ToString());
        } nTime3 = getTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = getTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = getTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);
    // Remove conflicting transactions from the mempool.;
    mempool.removeForBlock(blockConnecting.vtx, pidxNew->nHeight);
    disconnectpool.removeForBlock(blockConnecting.vtx);
    // Update chainActive & related variables.
    UpdateTip(pidxNew, chainparams);

    int64_t nTime6 = getTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);

    connectTrace.BlockConnected(pidxNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
static BLBlockIndex* findMostWorkChain() {
    do {
        BLBlockIndex *pidxNew = nullptr;

        // find the best candidate header. {
            std::set<BLBlockIndex*, BLBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pidxNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        BLBlockIndex *pidxTest = pidxNew;
        bool fInvalidAncestor = false;
        while (pidxTest && !chainActive.Contains(pidxTest)) {
            assert(pidxTest->nChainTx || pidxTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pidxTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pidxTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pidxBestInvalid == nullptr || pidxNew->nChainWork > pidxBestInvalid->nChainWork))
                    pidxBestInvalid = pidxNew;
                BLBlockIndex *pidxFailed = pidxNew;
                // Remove the entire chain from the set.
                while (pidxTest != pidxFailed) {
                    if (fFailedChain) {
                        pidxFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pidxFailed->pprev, pidxFailed));
                    }             setBlockIndexCandidates.erase(pidxFailed);
                    pidxFailed = pidxFailed->pprev;
                }         setBlockIndexCandidates.erase(pidxTest);
                fInvalidAncestor = true;
                break;
            }     pidxTest = pidxTest->pprev;
        } if (!fInvalidAncestor)
            return pidxNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
static void PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<BLBlockIndex*, BLBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pidxMostWork the active block.
 * pblock is either nullptr or a pointer to a BLBlock corresponding to pidxMostWork.
 */
static bool ActivateBestChainStep(CValidationState& state, const WBLChainParams& chainparams, BLBlockIndex* pidxMostWork, const std::shared_ptr<const BLBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace) {
    AssertLockHeld(cs_main);
    const BLBlockIndex *pidxOldTip = chainActive.Tip();
    const BLBlockIndex *pidxFork = chainActive.findFork(pidxMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Tip() && chainActive.Tip() != pidxFork) {
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        } fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<BLBlockIndex*> vpidxToConnect;
    bool fContinue = true;
    int nHeight = pidxFork ? pidxFork->nHeight : -1;
    while (fContinue && nHeight != pidxMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pidxMostWork->nHeight);
        vpidxToConnect.clear();
        vpidxToConnect.reserve(nTargetHeight - nHeight);
        BLBlockIndex *pidxIter = pidxMostWork->getAncestor(nTargetHeight);
        while (pidxIter && pidxIter->nHeight != nHeight) {
            vpidxToConnect.push_back(pidxIter);
            pidxIter = pidxIter->pprev;
        } nHeight = nTargetHeight;

        // Connect new blocks.
        for (BLBlockIndex *pidxConnect : reverse_iterate(vpidxToConnect)) {
            if (!ConnectTip(state, chainparams, pidxConnect, pidxConnect == pidxMostWork ? pblock : std::shared_ptr<const BLBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpidxToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }     } else {
                PruneBlockIndexCandidates();
                if (!pidxOldTip || chainActive.Tip()->nChainWork > pidxOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }     } }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);
    }
    mempool.check(pcoinsTip);

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpidxToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static void NotifyHeaderTip() {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static BLBlockIndex* pidxHeaderOld = nullptr;
    BLBlockIndex* pidxHeader = nullptr; {
        LOCK(cs_main);
        pidxHeader = pidxBestHeader;

        if (pidxHeader != pidxHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pidxHeaderOld = pidxHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pidxHeader);
    }
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either nullptr or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestChain(CValidationState &state, const WBLChainParams& chainparams, std::shared_ptr<const BLBlock> pblock) {
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!

    BLBlockIndex *pidxMostWork = nullptr;
    BLBlockIndex *pidxNewTip = nullptr;
    int nStopAtHeight = gArgs.getArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        boost::this_thread::interruption_point();
        if (ShutdownRequested())
            break;

        const BLBlockIndex *pidxFork;
        bool fInitialDownload; {
            LOCK(cs_main);
            ConnectTrace connectTrace(mempool); // Destructed before cs_main is unlocked

            BLBlockIndex *pidxOldTip = chainActive.Tip();
            if (pidxMostWork == nullptr) {
                pidxMostWork = findMostWorkChain();
            }

            // Whether we have anything to do at all.
            if (pidxMostWork == nullptr || pidxMostWork == chainActive.Tip())
                return true;

            bool fInvalidFound = false;
            std::shared_ptr<const BLBlock> nullBlockPtr;
            if (!ActivateBestChainStep(state, chainparams, pidxMostWork, pblock && pblock->getHash() == pidxMostWork->getBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace))
                return false;

            if (fInvalidFound) {
                // Wipe cache, we may need another branch now.
                pidxMostWork = nullptr;
            }     pidxNewTip = chainActive.Tip();
            pidxFork = chainActive.findFork(pidxOldTip);
            fInitialDownload = IsInitialBlockDownload();

            for (const PerBlockConnectTrace& trace : connectTrace.getBlocksConnected()) {
                assert(trace.pblock && trace.pidx);
                getMainSignals().BlockConnected(trace.pblock, trace.pidx, *trace.conflictedTxs);
            } } // When we reach this point, we switched to a new tip (stored in pidxNewTip).

        // Notifications/callbacks that can run without cs_main

        // Notify external listeners about the new tip.
        getMainSignals().UpdatedBlockTip(pidxNewTip, pidxFork, fInitialDownload);

        // Always notify the UI if a new block tip was connected
        if (pidxFork != pidxNewTip) {
            uiInterface.NotifyBlockTip(fInitialDownload, pidxNewTip);
        }

        if (nStopAtHeight && pidxNewTip && pidxNewTip->nHeight >= nStopAtHeight) StartShutdown();
    } while (pidxNewTip != pidxMostWork);
    CheckBlockIndex(chainparams.getConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_PERIODIC)) {
        return false;
    }

    return true;
}


bool PreciousBlock(CValidationState& state, const WBLChainParams& params, BLBlockIndex *pidx) { {
        LOCK(cs_main);
        if (pidx->nChainWork < chainActive.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        } if (chainActive.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        } nLastPreciousChainwork = chainActive.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pidx);
        pidx->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        } if (pidx->IsValid(BLOCK_VALID_TRANSACTIONS) && pidx->nChainTx) {
            setBlockIndexCandidates.insert(pidx);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, params);
}

bool InvalidateBlock(CValidationState& state, const WBLChainParams& chainparams, BLBlockIndex *pidx) {
    AssertLockHeld(cs_main);

    // Mark the block itself as invalid.
    pidx->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pidx);
    setBlockIndexCandidates.erase(pidx);

    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Contains(pidx)) {
        BLBlockIndex *pidxWalk = chainActive.Tip();
        pidxWalk->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(pidxWalk);
        setBlockIndexCandidates.erase(pidxWalk);
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // It's probably hopeless to try to make the mempool consistent
            // here if DisconnectTip failed, but we can try.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
    }

    // DisconnectTip will add transactions to disconnectpool; try to add these
    // back to the mempool.
    UpdateMempoolForReorg(disconnectpool, true);

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
            setBlockIndexCandidates.insert(it->second);
        } it++;
    }

    InvalidChainFound(pidx);
    uiInterface.NotifyBlockTip(IsInitialBlockDownload(), pidx->pprev);
    return true;
}

bool ResetBlockFailureFlags(BLBlockIndex *pidx) {
    AssertLockHeld(cs_main);

    int nHeight = pidx->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->getAncestor(nHeight) == pidx) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }     if (it->second == pidxBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pidxBestInvalid = nullptr;
            } } it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pidx != nullptr) {
        if (pidx->nStatus & BLOCK_FAILED_MASK) {
            pidx->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pidx);
        } pidx = pidx->pprev;
    }
    return true;
}

static BLBlockIndex* AddToBlockIndex(const BLBlockHeader& block) {
    // Check for duplicate
    uint256 hash = block.getHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    BLBlockIndex* pidxNew = new BLBlockIndex(block);
    assert(pidxNew);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pidxNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pidxNew)).first;
    pidxNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end()) {
        pidxNew->pprev = (*miPrev).second;
        pidxNew->nHeight = pidxNew->pprev->nHeight + 1;
        pidxNew->BuildSkip();
    }
    pidxNew->nTimeMax = (pidxNew->pprev ? std::max(pidxNew->pprev->nTimeMax, pidxNew->nTime) : pidxNew->nTime);
    pidxNew->nChainWork = (pidxNew->pprev ? pidxNew->pprev->nChainWork : 0) + getBlockProof(*pidxNew);
    pidxNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pidxBestHeader == nullptr || pidxBestHeader->nChainWork < pidxNew->nChainWork)
        pidxBestHeader = pidxNew;

    setDirtyBlockIndex.insert(pidxNew);

    return pidxNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
static bool ReceivedBlockTransactions(const BLBlock &block, CValidationState& state, BLBlockIndex *pidxNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams) {
    pidxNew->nTx = block.vtx.size();
    pidxNew->nChainTx = 0;
    pidxNew->nFile = pos.nFile;
    pidxNew->nDataPos = pos.nPos;
    pidxNew->nUndoPos = 0;
    pidxNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pidxNew->pprev, consensusParams)) {
        pidxNew->nStatus |= BLOCK_OPT_WITNESS;
    }
    pidxNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pidxNew);

    if (pidxNew->pprev == nullptr || pidxNew->pprev->nChainTx) {
        // If pidxNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<BLBlockIndex*> queue;
        queue.push_back(pidxNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            BLBlockIndex *pidx = queue.front();
            queue.pop_front();
            pidx->nChainTx = (pidx->pprev ? pidx->pprev->nChainTx : 0) + pidx->nTx; {
                LOCK(cs_nBlockSequenceId);
                pidx->nSequenceId = nBlockSequenceId++;
            }     if (chainActive.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pidx, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pidx);
            }     std::pair<std::multimap<BLBlockIndex*, BLBlockIndex*>::iterator, std::multimap<BLBlockIndex*, BLBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pidx);
            while (range.first != range.second) {
                std::multimap<BLBlockIndex*, BLBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            } }
    } else {
        if (pidxNew->pprev && pidxNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pidxNew->pprev, pidxNew));
        }
    }

    return true;
}

static bool findBlockPos(CValidationState &state, CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false) {
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            } } pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        } FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }     }     else
                return state.Error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

static bool findUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize) {
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            } } else
            return state.Error("out of disk space");
    }

    return true;
}

static bool CheckBlockHeader(const BLBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true) {
    // Check Equihash solution is valid
    bool postfork = block.nHeight >= (uint32_t)consensusParams.BLHeight;
    if (fCheckPOW && postfork && !CheckEquihashSolution(&block, Params())) {
        LogPrintf("CheckBlockHeader(): Equihash solution invalid at height %d\n", block.nHeight);
        return state.DoS(100, error("CheckBlockHeader(): Equihash solution invalid"),
                         REJECT_INVALID, "invalid-solution");
    }

    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.getHash(), block.nBits, postfork, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    return true;
}

bool CheckBlock(const BLBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot) {
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    int serialization_flags = SERIALIZE_TRANSACTION_NO_WITNESS;
    if (block.nHeight < (uint32_t)consensusParams.BLHeight) {
        serialization_flags |= SERIALIZE_BLOCK_LEGACY;
    }
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::getSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | serialization_flags) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    for (const auto& tx : block.vtx)
        if (!CheckTransaction(*tx, state, false))
            return state.Invalid(false, state.getRejectCode(), state.getRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->getHash().ToString(), state.getDebugMessage()));

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx) {
        nSigOps += getLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool IsWitnessEnabled(const BLBlockIndex* pidxPrev, const Consensus::Params& params) {
    LOCK(cs_main);
    return (VersionBitsState(pidxPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE);
}

// Compute at which vout of the block's coinbase transaction the witness
// commitment occurs, or -1 if not found.
static int getWitnessCommitmentIndex(const BLBlock& block) {
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            if (block.vtx[0]->vout[o].scriptPubKey.size() >= 38 && block.vtx[0]->vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0]->vout[o].scriptPubKey[1] == 0x24 && block.vtx[0]->vout[o].scriptPubKey[2] == 0xaa && block.vtx[0]->vout[o].scriptPubKey[3] == 0x21 && block.vtx[0]->vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0]->vout[o].scriptPubKey[5] == 0xed) {
                commitpos = o;
            } }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(BLBlock& block, const BLBlockIndex* pidxPrev, const Consensus::Params& consensusParams) {
    int commitpos = getWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pidxPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        BLMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(BLBlock& block, const BLBlockIndex* pidxPrev, const Consensus::Params& consensusParams) {
    std::vector<unsigned char> commitment;
    int commitpos = getWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr);
            CHash256().Write(witnessroot.begin(), 32).Write(ret.data(), 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            BLMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedBlockStructures(block, pidxPrev, consensusParams);
    return commitment;
}

/** Context-dependent validity checks.
 *  By "context", we mean only the previous block headers, but not the UTXO
 *  set; UTXO-related validity checks are done in ConnectBlock(). */
static bool ContextualCheckBlockHeader(const BLBlockHeader& block, CValidationState& state, const WBLChainParams& params, const BLBlockIndex* pidxPrev, int64_t nAdjustedTime) {
    assert(pidxPrev != nullptr);
    const int nHeight = pidxPrev->nHeight + 1;

    // Check proof of work
    const Consensus::Params& consensusParams = params.getConsensus();
    if (block.nBits != getNextWorkRequired(pidxPrev, &block, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // getLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // MapBlockIndex.
        BLBlockIndex* pcheckpoint = Checkpoints::getLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight)
            return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight), REJECT_CHECKPOINT, "bad-fork-prior-to-checkpoint");
    }

    // Check block height for blocks after BL fork.
    if (nHeight >= consensusParams.BLHeight && block.nHeight != (uint32_t)nHeight)
        return state.Invalid(false, REJECT_INVALID, "bad-height", "incorrect block height");

    // Check timestamp against prev
    if (block.getBlockTime() <= pidxPrev->getMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.getBlockTime() > nAdjustedTime + MAX_FUTURE_BLOCK_TIME)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
       (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
       (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}

static bool ContextualCheckBlock(const BLBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const BLBlockIndex* pidxPrev) {
    const int nHeight = pidxPrev == nullptr ? 0 : pidxPrev->nHeight + 1;

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pidxPrev, consensusParams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pidxPrev->getMedianTimePast()
                              : block.getBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= consensusParams.BIP34Height) {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }

    if (nHeight >= consensusParams.BLHeight &&
        nHeight < consensusParams.BLHeight + consensusParams.BLPremineWindow &&
        consensusParams.BLPremineEnforceWhitelist) {
        if (block.vtx[0]->vout.size() != 1) {
            return state.DoS(
                100, error("%s: only one coinbase output is allowed",__func__),
                REJECT_INVALID, "bad-premine-coinbase-output");
        } const CTxOut& output = block.vtx[0]->vout[0];
        bool valid = Params().IsPremineAddressScript(output.scriptPubKey, (uint32_t)nHeight);
        if (!valid) {
            return state.DoS(
                100, error("%s: not in premine whitelist", __func__),
                REJECT_INVALID, "bad-premine-coinbase-scriptpubkey");
        }
    }


    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (VersionBitsState(pidxPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE) {
        int commitpos = getWitnessCommitmentIndex(block);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-nonce-size", true, strprintf("%s : invalid witness nonce size", __func__));
            }     CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-merkle-match", true, strprintf("%s : witness merkle commitment mismatch", __func__));
            }     fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
      for (const auto& tx : block.vtx) {
            if (tx->HasWitness()) {
                return state.DoS(100, false, REJECT_INVALID, "unexpected-witness", true, strprintf("%s : unexpected witness data found", __func__));
            } }
    }

    // After the coinbase witness nonce and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    if (getBlockWeight(block, consensusParams) > MAX_BLOCK_WEIGHT) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-weight", false, strprintf("%s : weight limit failed", __func__));
    }

    return true;
}

static bool AcceptBlockHeader(const BLBlockHeader& block, CValidationState& state, const WBLChainParams& chainparams, BLBlockIndex** ppidx) {
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.getHash();
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    BLBlockIndex *pidx = nullptr;
    if (hash != chainparams.getConsensus().hashGenesisBlock) {

        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pidx = miSelf->second;
            if (ppidx)
                *ppidx = pidx;
            if (pidx->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!CheckBlockHeader(block, state, chainparams.getConsensus()))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        // get prev block index
        BLBlockIndex* pidxPrev = nullptr;
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "prev-blk-not-found");
        pidxPrev = (*mi).second;
        if (pidxPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
        if (!ContextualCheckBlockHeader(block, state, chainparams, pidxPrev, getAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));
    }
    if (pidx == nullptr)
        pidx = AddToBlockIndex(block);

    if (ppidx)
        *ppidx = pidx;

    CheckBlockIndex(chainparams.getConsensus());

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<BLBlockHeader>& headers, CValidationState& state, const WBLChainParams& chainparams, const BLBlockIndex** ppidx) { {
        LOCK(cs_main);
        for (const BLBlockHeader& header : headers) {
            BLBlockIndex *pidx = nullptr; // Use a temp pidx instead of ppidx to avoid a const_cast
            if (!AcceptBlockHeader(header, state, chainparams, &pidx)) {
                return false;
            }     if (ppidx) {
                *ppidx = pidx;
            } }
    }
    NotifyHeaderTip();
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
static bool AcceptBlock(const std::shared_ptr<const BLBlock>& pblock, CValidationState& state, const WBLChainParams& chainparams, BLBlockIndex** ppidx, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock) {
    const BLBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    BLBlockIndex *pidxDummy = nullptr;
    BLBlockIndex *&pidx = ppidx ? *ppidx : pidxDummy;

    if (!AcceptBlockHeader(block, state, chainparams, &pidx))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pidx->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (chainActive.Tip() ? pidx->nChainWork > chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pidx->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pidx->nTx != 0) return true;  // This is a previously-processed block that was pruned
        if (!fHasMoreWork) return true;     // Don't process less-work chains
        if (fTooFarAhead) return true;      // Block height is too high
    }
    if (fNewBlock) *fNewBlock = true;

    if (!CheckBlock(block, state, chainparams.getConsensus()) ||
        !ContextualCheckBlock(block, state, chainparams.getConsensus(), pidx->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pidx->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pidx);
        } return error("%s: %s", __func__, FormatStateMessage(state));
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!IsInitialBlockDownload() && chainActive.Tip() == pidx->pprev)
        getMainSignals().NewPoWValidBlock(pidx, pblock);

    int nHeight = pidx->nHeight;

    // Write block to history file
    try {
        unsigned int nBlockSize = ::getSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != nullptr)
            blockPos = *dbp;
        if (!findBlockPos(state, blockPos, nBlockSize+8, nHeight, block.getBlockTime(), dbp != nullptr))
            return error("AcceptBlock(): findBlockPos failed");
        if (dbp == nullptr)
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                AbortNode(state, "Failed to write block");
        if (!ReceivedBlockTransactions(block, state, pidx, blockPos, chainparams.getConsensus()))
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE); // we just allocated more disk space for block files

    return true;
}

bool ProcessNewBlock(const WBLChainParams& chainparams, const std::shared_ptr<const BLBlock> pblock, bool fForceProcessing, bool *fNewBlock) { {
        BLBlockIndex *pidx = nullptr;
        if (fNewBlock) *fNewBlock = false;
        CValidationState state;
        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state, chainparams.getConsensus());

        LOCK(cs_main);

        if (ret) {
            // Store to disk
            ret = AcceptBlock(pblock, state, chainparams, &pidx, fForceProcessing, nullptr, fNewBlock);
        } CheckBlockIndex(chainparams.getConsensus());
        if (!ret) {
            getMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED", __func__);
        }
    }

    NotifyHeaderTip();

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed", __func__);

    return true;
}

bool TestBlockValidity(CValidationState& state, const WBLChainParams& chainparams, const BLBlock& block, BLBlockIndex* pidxPrev, bool fCheckPOW, bool fCheckMerkleRoot) {
    AssertLockHeld(cs_main);
    assert(pidxPrev && pidxPrev == chainActive.Tip());
    CCoinsViewCache viewNew(pcoinsTip);
    BLBlockIndex indexDummy(block);
    indexDummy.pprev = pidxPrev;
    indexDummy.nHeight = pidxPrev->nHeight + 1;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainparams, pidxPrev, getAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
    if (!CheckBlock(block, state, chainparams.getConsensus(), fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBlock(block, state, chainparams.getConsensus(), pidxPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
static uint64_t CalculateCurrentUsage() {
    uint64_t retval = 0;
    for (const BLBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber) {
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it) {
        BLBlockIndex* pidx = it->second;
        if (pidx->nFile == fileNumber) {
            pidx->nStatus &= ~BLOCK_HAVE_DATA;
            pidx->nStatus &= ~BLOCK_HAVE_UNDO;
            pidx->nFile = 0;
            pidx->nDataPos = 0;
            pidx->nUndoPos = 0;
            setDirtyBlockIndex.insert(pidx);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<BLBlockIndex*, BLBlockIndex*>::iterator, std::multimap<BLBlockIndex*, BLBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pidx->pprev);
            while (range.first != range.second) {
                std::multimap<BLBlockIndex *, BLBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pidx) {
                    mapBlocksUnlinked.erase(_it);
                }     } }
    }

    vinfoBlockFile[fileNumber].setNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune) {
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        fs::remove(getBlockPosFilename(pos, "blk"));
        fs::remove(getBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
static void findFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight) {
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight) {
    CValidationState state;
    const WBLChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE, nManualPruneHeight);
}

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
static void findFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight) {
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)chainActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint(BCLog::PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes) {
    uint64_t nFreeBytesAvailable = fs::space(getDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

static FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly) {
    if (pos.IsNull())
        return nullptr;
    fs::path path = getBlockPosFilename(pos, prefix);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return nullptr;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

/** Open an undo file (rev?????.dat) */
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

fs::path getBlockPosFilename(const CDiskBlockPos &pos, const char *prefix) {
    return getDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

BLBlockIndex * InsertBlockIndex(uint256 hash) {
    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    BLBlockIndex* pidxNew = new BLBlockIndex();
    if (!pidxNew)
        throw std::runtime_error(std::string(__func__) + ": new BLBlockIndex failed");
    mi = mapBlockIndex.insert(std::make_pair(hash, pidxNew)).first;
    pidxNew->phashBlock = &((*mi).first);

    return pidxNew;
}

bool static LoadBlockIndexDB(const WBLChainParams& chainparams) {
    if (!pblocktree->LoadBlockIndexGuts(chainparams.getConsensus(), InsertBlockIndex))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    std::vector<std::pair<int, BLBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const std::pair<uint256, BLBlockIndex*>& item : mapBlockIndex) {
        BLBlockIndex* pidx = item.second;
        vSortedByHeight.push_back(std::make_pair(pidx->nHeight, pidx));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, BLBlockIndex*>& item : vSortedByHeight) {
        BLBlockIndex* pidx = item.second;
        pidx->nChainWork = (pidx->pprev ? pidx->pprev->nChainWork : 0) + getBlockProof(*pidx);
        pidx->nTimeMax = (pidx->pprev ? std::max(pidx->pprev->nTimeMax, pidx->nTime) : pidx->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pidx->nTx > 0) {
            if (pidx->pprev) {
                if (pidx->pprev->nChainTx) {
                    pidx->nChainTx = pidx->pprev->nChainTx + pidx->nTx;
                } else {
                    pidx->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pidx->pprev, pidx));
                }     } else {
                pidx->nChainTx = pidx->nTx;
            } } if (pidx->IsValid(BLOCK_VALID_TRANSACTIONS) && (pidx->nChainTx || pidx->pprev == nullptr))
            setBlockIndexCandidates.insert(pidx);
        if (pidx->nStatus & BLOCK_FAILED_MASK && (!pidxBestInvalid || pidx->nChainWork > pidxBestInvalid->nChainWork))
            pidxBestInvalid = pidx;
        if (pidx->pprev)
            pidx->BuildSkip();
        if (pidx->IsValid(BLOCK_VALID_TREE) && (pidxBestHeader == nullptr || BLBlockIndexWorkComparator()(pidxBestHeader, pidx)))
            pidxBestHeader = pidx;
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        BLBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<uint256, BLBlockIndex*>& item : mapBlockIndex) {
        BLBlockIndex* pidx = item.second;
        if (pidx->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pidx->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++) {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("%s: transaction index %s\n", __func__, fTxIndex ? "enabled" : "disabled");

    return true;
}

bool LoadChainTip(const WBLChainParams& chainparams) {
    if (chainActive.Tip() && chainActive.Tip()->getBlockHash() == pcoinsTip->getBestBlock()) return true;

    if (pcoinsTip->getBestBlock().IsNull() && mapBlockIndex.size() == 1) {
        // In case we just added the genesis block, connect it now, so
        // that we always have a chainActive.Tip() when we return.
        LogPrintf("%s: Connecting genesis block...\n", __func__);
        CValidationState state;
        if (!ActivateBestChain(state, chainparams)) {
            return false;
        }
    }

    // Load pointer to end of best chain
    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->getBestBlock());
    if (it == mapBlockIndex.end())
        return false;
    chainActive.setInfo(it->second);

    PruneBlockIndexCandidates();

    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
        chainActive.Tip()->getBlockHash().ToString(), chainActive.Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->getBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), chainActive.Tip()));
    return true;
}

CVerifyDB::CVerifyDB() {
    uiInterface.ShowProgress(_("Verifying blocks..."), 0);
}

CVerifyDB::~CVerifyDB() {
    uiInterface.ShowProgress("", 100);
}

bool CVerifyDB::VerifyDB(const WBLChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth) {
    LOCK(cs_main);
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    BLBlockIndex* pidxState = chainActive.Tip();
    BLBlockIndex* pidxFailure = nullptr;
    int nGoodTransactions = 0;
    CValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]...");
    for (BLBlockIndex* pidx = chainActive.Tip(); pidx && pidx->pprev; pidx = pidx->pprev) {
        boost::this_thread::interruption_point();
        int percentageDone = std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pidx->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone);
            reportDone = percentageDone/10;
        } uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone);
        if (pidx->nHeight < chainActive.Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pidx->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("VerifyDB(): block verification stopping at height %d (pruning, no data)\n", pidx->nHeight);
            break;
        } BLBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pidx, chainparams.getConsensus()))
            return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pidx->nHeight, pidx->getBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, chainparams.getConsensus()))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pidx->nHeight, pidx->getBlockHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pidx) {
            BLBlockUndo undo;
            CDiskBlockPos pos = pidx->getUndoPos();
            if (!pos.IsNull()) {
                if (!UndoReadFromDisk(undo, pos, pidx->pprev->getBlockHash()))
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pidx->nHeight, pidx->getBlockHash().ToString());
            } } // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pidx == pidxState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            assert(coins.getBestBlock() == pidx->getBlockHash());
            DisconnectResult res = DisconnectBlock(block, pidx, coins);
            if (res == DISCONNECT_FAILED) {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s", pidx->nHeight, pidx->getBlockHash().ToString());
            }     pidxState = pidx->pprev;
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pidxFailure = pidx;
            } else {
                nGoodTransactions += block.vtx.size();
            } } if (ShutdownRequested())
            return true;
    }
    if (pidxFailure)
        return error("VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pidxFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        BLBlockIndex *pidx = pidxState;
        while (pidx != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pidx->nHeight)) / (double)nCheckDepth * 50))));
            pidx = chainActive.Next(pidx);
            BLBlock block;
            if (!ReadBlockFromDisk(block, pidx, chainparams.getConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pidx->nHeight, pidx->getBlockHash().ToString());
            if (!ConnectBlock(block, state, pidx, coins, chainparams))
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s", pidx->nHeight, pidx->getBlockHash().ToString());
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pidxState->nHeight, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
static bool RollforwardBlock(const BLBlockIndex* pidx, CCoinsViewCache& inputs, const WBLChainParams& params) {
    // TODO: merge with ConnectBlock
    BLBlock block;
    if (!ReadBlockFromDisk(block, pidx, params.getConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pidx->nHeight, pidx->getBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            } } // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pidx->nHeight, true);
    }
    return true;
}

bool ReplayBlocks(const WBLChainParams& params, CCoinsView* view) {
    LOCK(cs_main);

    CCoinsViewCache cache(view);

    std::vector<uint256> hashHeads = view->getHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks..."), 0);
    LogPrintf("Replaying blocks\n");

    const BLBlockIndex* pidxOld = nullptr;  // Old tip during the interrupted flush.
    const BLBlockIndex* pidxNew;            // New tip during the interrupted flush.
    const BLBlockIndex* pidxFork = nullptr; // Latest block common to both the old and the new tip.

    if (mapBlockIndex.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pidxNew = mapBlockIndex[hashHeads[0]];

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (mapBlockIndex.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        } pidxOld = mapBlockIndex[hashHeads[1]];
        pidxFork = LastCommonAncestor(pidxOld, pidxNew);
        assert(pidxFork != nullptr);
    }

    // Rollback along the old branch.
    while (pidxOld != pidxFork) {
        if (pidxOld->nHeight > 0) { // Never disconnect the genesis block.
            BLBlock block;
            if (!ReadBlockFromDisk(block, pidxOld, params.getConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pidxOld->nHeight, pidxOld->getBlockHash().ToString());
            }     LogPrintf("Rolling back %s (%i)\n", pidxOld->getBlockHash().ToString(), pidxOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pidxOld, cache);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pidxOld->nHeight, pidxOld->getBlockHash().ToString());
            }     // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        } pidxOld = pidxOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pidxFork ? pidxFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pidxNew->nHeight; ++nHeight) {
        const BLBlockIndex* pidx = pidxNew->getAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pidx->getBlockHash().ToString(), nHeight);
        if (!RollforwardBlock(pidx, cache, params)) return false;
    }

    cache.setBestBlock(pidxNew->getBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100);
    return true;
}

bool RewindBlockIndex(const WBLChainParams& params) {
    LOCK(cs_main);

    // Note that during -reindex-chainstate we are called with an empty chainActive!

    int nHeight = 1;
    while (nHeight <= chainActive.Height()) {
        if (IsWitnessEnabled(chainActive[nHeight - 1], params.getConsensus()) && !(chainActive[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
            break;
        } nHeight++;
    }

    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1
    CValidationState state;
    BLBlockIndex* pidx = chainActive.Tip();
    while (chainActive.Height() >= nHeight) {
        if (fPruneMode && !(chainActive.Tip()->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, don't try rewinding past the HAVE_DATA point;
            // since older blocks can't be served anyway, there's
            // no need to walk further, and trying to DisconnectTip()
            // will fail (and require a needless reindex/redownload
            // of the blockchain).
            break;
        } if (!DisconnectTip(state, params, nullptr)) {
            return error("RewindBlockIndex: unable to disconnect block at height %i", pidx->nHeight);
        } // Occasionally flush state to disk.
        if (!FlushStateToDisk(params, state, FLUSH_STATE_PERIODIC))
            return false;
    }

    // Reduce validity flag and have-data flags.
    // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
    // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        BLBlockIndex* pidxIter = it->second;

        // Note: If we encounter an insufficiently validated block that
        // is on chainActive, it must be because we are a pruning node, and
        // this block or some successor doesn't HAVE_DATA, so we were unable to
        // rewind all the way.  Blocks remaining on chainActive at this point
        // must not have their validity reduced.
        if (IsWitnessEnabled(pidxIter->pprev, params.getConsensus()) && !(pidxIter->nStatus & BLOCK_OPT_WITNESS) && !chainActive.Contains(pidxIter)) {
            // Reduce validity
            pidxIter->nStatus = std::min<unsigned int>(pidxIter->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (pidxIter->nStatus & ~BLOCK_VALID_MASK);
            // Remove have-data flags.
            pidxIter->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
            // Remove storage location.
            pidxIter->nFile = 0;
            pidxIter->nDataPos = 0;
            pidxIter->nUndoPos = 0;
            // Remove various other things
            pidxIter->nTx = 0;
            pidxIter->nChainTx = 0;
            pidxIter->nSequenceId = 0;
            // Make sure it gets written.
            setDirtyBlockIndex.insert(pidxIter);
            // Update indexes
            setBlockIndexCandidates.erase(pidxIter);
            std::pair<std::multimap<BLBlockIndex*, BLBlockIndex*>::iterator, std::multimap<BLBlockIndex*, BLBlockIndex*>::iterator> ret = mapBlocksUnlinked.equal_range(pidxIter->pprev);
            while (ret.first != ret.second) {
                if (ret.first->second == pidxIter) {
                    mapBlocksUnlinked.erase(ret.first++);
                } else {
                    ++ret.first;
                }     } } else if (pidxIter->IsValid(BLOCK_VALID_TRANSACTIONS) && pidxIter->nChainTx) {
            setBlockIndexCandidates.insert(pidxIter);
        }
    }

    if (chainActive.Tip() != nullptr) {
        // We can't prune block index candidates based on our tip if we have
        // no tip due to chainActive being empty!
        PruneBlockIndexCandidates();

        CheckBlockIndex(params.getConsensus());

        // FlushStateToDisk can possibly read chainActive. Be conservative
        // and skip it here, we're about to -reindex-chainstate anyway, so
        // it'll get called a bunch real soon.
        if (!FlushStateToDisk(params, state, FLUSH_STATE_ALWAYS)) {
            return false;
        }
    }

    return true;
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex() {
    LOCK(cs_main);
    setBlockIndexCandidates.clear();
    chainActive.setInfo(nullptr);
    pidxBestInvalid = nullptr;
    pidxBestHeader = nullptr;
    mempool.clear();
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    nBlockSequenceId = 1;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }

    for (BlockMap::value_type& entry : mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
    fHavePruned = false;
}

bool LoadBlockIndex(const WBLChainParams& chainparams) {
    // Load block index from databases
    bool needs_init = fReindex;
    if (!fReindex) {
        bool ret = LoadBlockIndexDB(chainparams);
        if (!ret) return false;
        needs_init = mapBlockIndex.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
        // Use the provided setting for -txindex in the new database
        fTxIndex = gArgs.getBoolArg("-txindex", DEFAULT_TXINDEX);
        pblocktree->WriteFlag("txindex", fTxIndex);
    }
    return true;
}

bool LoadGenesisBlock(const WBLChainParams& chainparams) {
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // mapBlockIndex. Note that we can't use chainActive here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (mapBlockIndex.count(chainparams.GenesisBlock().getHash()))
        return true;

    try {
        BLBlock &block = const_cast<BLBlock&>(chainparams.GenesisBlock());
        // Start new block file
        unsigned int nBlockSize = ::getSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        CValidationState state;
        if (!findBlockPos(state, blockPos, nBlockSize+8, 0, block.getBlockTime()))
            return error("%s: findBlockPos failed", __func__);
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
            return error("%s: writing genesis block to disk failed", __func__);
        BLBlockIndex *pidx = AddToBlockIndex(block);
        if (!ReceivedBlockTransactions(block, state, pidx, blockPos, chainparams.getConsensus()))
            return error("%s: genesis block not accepted", __func__);
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

bool LoadExternalBlockFile(const WBLChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp) {
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = getTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.getPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.setPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.setLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.findByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.getPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }     try {
                // read block
                uint64_t nBlockPos = blkdat.getPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.setLimit(nBlockPos + nSize);
                blkdat.setPos(nBlockPos);
                std::shared_ptr<BLBlock> pblock = std::make_shared<BLBlock>();
                BLBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.getPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.getHash();
                if (hash != chainparams.getConsensus().hashGenesisBlock && mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                    LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                            block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0) {
                    LOCK(cs_main);
                    CValidationState state;
                    if (AcceptBlock(pblock, state, chainparams, nullptr, true, dbp, nullptr))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != chainparams.getConsensus().hashGenesisBlock && mapBlockIndex[hash]->nHeight % 1000 == 0) {
                    LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), mapBlockIndex[hash]->nHeight);
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.getConsensus().hashGenesisBlock) {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }         }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        std::shared_ptr<BLBlock> pblockrecursive = std::make_shared<BLBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.getConsensus()))
                        {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->getHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            CValidationState dummy;
                            if (AcceptBlock(pblockrecursive, dummy, chainparams, nullptr, true, &it->second, nullptr))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->getHash());
                            }                 }                 range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }         }     } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            } }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, getTimeMillis() - nStart);
    return nLoaded > 0;
}

void static CheckBlockIndex(const Consensus::Params& consensusParams) {
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<BLBlockIndex*,BLBlockIndex*> forward;
    for (BlockMap::iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); it++) {
        forward.insert(std::make_pair(it->second->pprev, it->second));
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator,std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    BLBlockIndex *pidx = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    BLBlockIndex* pidxFirstInvalid = nullptr; // Oldest ancestor of pidx which is invalid.
    BLBlockIndex* pidxFirstMissing = nullptr; // Oldest ancestor of pidx which does not have BLOCK_HAVE_DATA.
    BLBlockIndex* pidxFirstNeverProcessed = nullptr; // Oldest ancestor of pidx for which nTx == 0.
    BLBlockIndex* pidxFirstNotTreeValid = nullptr; // Oldest ancestor of pidx which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    BLBlockIndex* pidxFirstNotTransactionsValid = nullptr; // Oldest ancestor of pidx which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    BLBlockIndex* pidxFirstNotChainValid = nullptr; // Oldest ancestor of pidx which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    BLBlockIndex* pidxFirstNotScriptsValid = nullptr; // Oldest ancestor of pidx which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pidx != nullptr) {
        nNodes++;
        if (pidxFirstInvalid == nullptr && pidx->nStatus & BLOCK_FAILED_VALID) pidxFirstInvalid = pidx;
        if (pidxFirstMissing == nullptr && !(pidx->nStatus & BLOCK_HAVE_DATA)) pidxFirstMissing = pidx;
        if (pidxFirstNeverProcessed == nullptr && pidx->nTx == 0) pidxFirstNeverProcessed = pidx;
        if (pidx->pprev != nullptr && pidxFirstNotTreeValid == nullptr && (pidx->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pidxFirstNotTreeValid = pidx;
        if (pidx->pprev != nullptr && pidxFirstNotTransactionsValid == nullptr && (pidx->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pidxFirstNotTransactionsValid = pidx;
        if (pidx->pprev != nullptr && pidxFirstNotChainValid == nullptr && (pidx->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pidxFirstNotChainValid = pidx;
        if (pidx->pprev != nullptr && pidxFirstNotScriptsValid == nullptr && (pidx->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pidxFirstNotScriptsValid = pidx;

        // Begin: actual consistency checks.
        if (pidx->pprev == nullptr) {
            // Genesis block checks.
            assert(pidx->getBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pidx == chainActive.Genesis()); // The current active chain's genesis block must be this block.
        } if (pidx->nChainTx == 0) assert(pidx->nSequenceId <= 0);  // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pidx->nStatus & BLOCK_HAVE_DATA) == (pidx->nTx == 0));
            assert(pidxFirstMissing == pidxFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pidx->nStatus & BLOCK_HAVE_DATA) assert(pidx->nTx > 0);
        } if (pidx->nStatus & BLOCK_HAVE_UNDO) assert(pidx->nStatus & BLOCK_HAVE_DATA);
        assert(((pidx->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pidx->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pidxFirstNeverProcessed != nullptr) == (pidx->nChainTx == 0)); // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pidxFirstNotTransactionsValid != nullptr) == (pidx->nChainTx == 0));
        assert(pidx->nHeight == nHeight); // nHeight must be consistent.
        assert(pidx->pprev == nullptr || pidx->nChainWork >= pidx->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pidx->pskip && (pidx->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pidxFirstNotTreeValid == nullptr); // All mapBlockIndex entries must at least be TREE valid
        if ((pidx->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pidxFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pidx->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pidxFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pidx->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pidxFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pidxFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pidx->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        } if (!BLBlockIndexWorkComparator()(pidx, chainActive.Tip()) && pidxFirstNeverProcessed == nullptr) {
            if (pidxFirstInvalid == nullptr) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pidxFirstMissing == nullptr || pidx == chainActive.Tip()) {
                    assert(setBlockIndexCandidates.count(pidx));
                }         // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            } } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pidx) == 0);
        } // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator,std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pidx->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pidx->pprev);
            if (rangeUnlinked.first->second == pidx) {
                foundInUnlinked = true;
                break;
            }     rangeUnlinked.first++;
        } if (pidx->pprev && (pidx->nStatus & BLOCK_HAVE_DATA) && pidxFirstNeverProcessed != nullptr && pidxFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        } if (!(pidx->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pidxFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pidx->pprev && (pidx->nStatus & BLOCK_HAVE_DATA) && pidxFirstNeverProcessed == nullptr && pidxFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between chainActive and the
            //    tip.
            // So if this block is itself better than chainActive.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!BLBlockIndexWorkComparator()(pidx, chainActive.Tip()) && setBlockIndexCandidates.count(pidx) == 0) {
                if (pidxFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }     } } // assert(pidx->getBlockHash() == pidx->getBlockHeader().getHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator,std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator> range = forward.equal_range(pidx);
        if (range.first != range.second) {
            // A subnode was found.
            pidx = range.first->second;
            nHeight++;
            continue;
        } // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pidx) {
            // We are going to either move to a parent or a sibling of pidx.
            // If pidx was the first with a certain property, unset the corresponding variable.
            if (pidx == pidxFirstInvalid) pidxFirstInvalid = nullptr;
            if (pidx == pidxFirstMissing) pidxFirstMissing = nullptr;
            if (pidx == pidxFirstNeverProcessed) pidxFirstNeverProcessed = nullptr;
            if (pidx == pidxFirstNotTreeValid) pidxFirstNotTreeValid = nullptr;
            if (pidx == pidxFirstNotTransactionsValid) pidxFirstNotTransactionsValid = nullptr;
            if (pidx == pidxFirstNotChainValid) pidxFirstNotChainValid = nullptr;
            if (pidx == pidxFirstNotScriptsValid) pidxFirstNotScriptsValid = nullptr;
            // find our parent.
            BLBlockIndex* pidxPar = pidx->pprev;
            // find which child we just visited.
            std::pair<std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator,std::multimap<BLBlockIndex*,BLBlockIndex*>::iterator> rangePar = forward.equal_range(pidxPar);
            while (rangePar.first->second != pidx) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }     // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pidx = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pidx = pidxPar;
                nHeight--;
                continue;
            } }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string BLBlockFileInfo::ToString() const {
    return strprintf("BLBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}

BLBlockFileInfo* getBlockFileInfo(size_t n) {
    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos) {
    LOCK(cs_main);
    return VersionBitsState(chainActive.Tip(), params, pos, versionbitscache);
}

BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos) {
    LOCK(cs_main);
    return VersionBitsStatistics(chainActive.Tip(), params, pos);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos) {
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(chainActive.Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(void) {
    const WBLChainParams& chainparams = Params();
    int64_t nExpiryTimeout = gArgs.getArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(getDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t skipped = 0;
    int64_t failed = 0;
    int64_t nNow = getTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        } uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                mempool.PrioritiseTransaction(tx->getHash(), amountdelta);
            }     CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(chainparams, mempool, state, tx, true, nullptr, nTime, nullptr, false, 0);
                if (state.IsValid()) {
                    ++count;
                } else {
                    ++failed;
                }     } else {
                ++skipped;
            }     if (ShutdownRequested())
                return false;
        } std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            mempool.PrioritiseTransaction(i.first, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i successes, %i failed, %i expired\n", count, failed, skipped);
    return true;
}

void DumpMempool(void) {
    int64_t start = getTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;
 {
        LOCK(mempool.cs);
        for (const auto &i : mempool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        } vinfo = mempool.infoAll();
    }

    int64_t mid = getTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(getDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->getHash());
        }

        file << mapDeltas;
        FileCommit(file.get());
        file.fclose();
        RenameOver(getDataDir() / "mempool.dat.new", getDataDir() / "mempool.dat");
        int64_t last = getTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*0.000001, (last-mid)*0.000001);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
    }
}

//! Guess how far we are in the verification process at the given block index
double GuessVerificationProgress(const ChainTxData& data, BLBlockIndex *pidx) {
    if (pidx == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pidx->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pidx->nChainTx + (nNow - pidx->getBlockTime()) * data.dTxRate;
    }

    return pidx->nChainTx / fTxTotal;
}

class BLMainCleanup {
public:
    BLMainCleanup() {}
    ~BLMainCleanup() {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
