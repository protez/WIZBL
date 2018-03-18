// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WIZBL_VALIDATIONINTERFACE_H
#define WIZBL_VALIDATIONINTERFACE_H

#include <memory>

#include "wizbl/blockchain/primitives/transaction.h" // CTransaction(Ref)

class BLBlock;
class BLBlockIndex;
struct BLBlockLocator;
class BLBlockIndex;
class CConnman;
class CReserveScript;
class CValidationInterface;
class CValidationState;
class uint256;
class CScheduler;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();

class CValidationInterface {
protected:
    /** Notifies listeners of updated block chain tip */
    virtual void UpdatedBlockTip(const BLBlockIndex *pidxNew, const BLBlockIndex *pidxFork, bool fInitialDownload) {}
    /** Notifies listeners of a transaction having been added to mempool. */
    virtual void TransactionAddedToMempool(const CTransactionRef &ptxn) {}
    /**
     * Notifies listeners of a block being connected.
     * Provides a vector of transactions evicted from the mempool as a result.
     */
    virtual void BlockConnected(const std::shared_ptr<const BLBlock> &block, const BLBlockIndex *pidx, const std::vector<CTransactionRef> &txnConflicted) {}
    /** Notifies listeners of a block being disconnected */
    virtual void BlockDisconnected(const std::shared_ptr<const BLBlock> &block) {}
    /** Notifies listeners of the new active block chain on-disk. */
    virtual void setBestChain(const BLBlockLocator &locator) {}
    /** Notifies listeners about an inventory item being seen on the network. */
    virtual void Inventory(const uint256 &hash) {}
    /** Tells listeners to broadcast their data. */
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman) {}
    /**
     * Notifies listeners of a block validation result.
     * If the provided CValidationState IsValid, the provided block
     * is guaranteed to be the current best block at the time the
     * callback was generated (not necessarily now)
     */
    virtual void BlockChecked(const BLBlock&, const CValidationState&) {}
    /**
     * Notifies listeners that a block which builds directly on our current tip
     * has been received and connected to the headers tree, though not validated yet */
    virtual void NewPoWValidBlock(const BLBlockIndex *pidx, const std::shared_ptr<const BLBlock>& block) {};
    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

struct MainSignalsInstance;
class BLMainSignals {
private:
    std::unique_ptr<MainSignalsInstance> m_internals;

    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();

public:
    /** Register a CScheduler to give callbacks which should run in the background (may only be called once) */
    void RegisterBackgroundSignalScheduler(CScheduler& scheduler);
    /** Unregister a CScheduler to give callbacks which should run in the background - these callbacks will now be dropped! */
    void UnregisterBackgroundSignalScheduler();
    /** Call any remaining callbacks on the calling thread */
    void FlushBackgroundCallbacks();

    void UpdatedBlockTip(const BLBlockIndex *, const BLBlockIndex *, bool fInitialDownload);
    void TransactionAddedToMempool(const CTransactionRef &);
    void BlockConnected(const std::shared_ptr<const BLBlock> &, const BLBlockIndex *pidx, const std::vector<CTransactionRef> &);
    void BlockDisconnected(const std::shared_ptr<const BLBlock> &);
    void setBestChain(const BLBlockLocator &);
    void Inventory(const uint256 &);
    void Broadcast(int64_t nBestBlockTime, CConnman* connman);
    void BlockChecked(const BLBlock&, const CValidationState&);
    void NewPoWValidBlock(const BLBlockIndex *, const std::shared_ptr<const BLBlock>&);
};

BLMainSignals& getMainSignals();

#endif // WIZBL_VALIDATIONINTERFACE_H
