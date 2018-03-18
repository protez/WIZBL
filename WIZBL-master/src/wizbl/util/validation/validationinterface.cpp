// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wizbl/util/validation/validationinterface.h"
#include "init.h"
#include "scheduler.h"
#include "wizbl/blockchain/net/sync.h"
#include "wizbl/blockchain/util/util.h"

#include <list>
#include <atomic>

#include <boost/signals2/signal.hpp>

struct MainSignalsInstance {
    boost::signals2::signal<void (const BLBlockIndex *, const BLBlockIndex *, bool fInitialDownload)> UpdatedBlockTip;
    boost::signals2::signal<void (const CTransactionRef &)> TransactionAddedToMempool;
    boost::signals2::signal<void (const std::shared_ptr<const BLBlock> &, const BLBlockIndex *pidx, const std::vector<CTransactionRef>&)> BlockConnected;
    boost::signals2::signal<void (const std::shared_ptr<const BLBlock> &)> BlockDisconnected;
    boost::signals2::signal<void (const BLBlockLocator &)> setBestChain;
    boost::signals2::signal<void (const uint256 &)> Inventory;
    boost::signals2::signal<void (int64_t nBestBlockTime, CConnman* connman)> Broadcast;
    boost::signals2::signal<void (const BLBlock&, const CValidationState&)> BlockChecked;
    boost::signals2::signal<void (const BLBlockIndex *, const std::shared_ptr<const BLBlock>&)> NewPoWValidBlock;

    // We are not allowed to assume the scheduler only runs in one thread,
    // but must ensure all callbacks happen in-order, so we end up creating
    // our own queue here :(
    SingleThreadedSchedulerClient m_schedulerClient;

    MainSignalsInstance(CScheduler *pscheduler) : m_schedulerClient(pscheduler) {}
};

static BLMainSignals g_signals;

void BLMainSignals::RegisterBackgroundSignalScheduler(CScheduler& scheduler) {
    assert(!m_internals);
    m_internals.reset(new MainSignalsInstance(&scheduler));
}

void BLMainSignals::UnregisterBackgroundSignalScheduler() {
    m_internals.reset(nullptr);
}

void BLMainSignals::FlushBackgroundCallbacks() {
    m_internals->m_schedulerClient.EmptyQueue();
}

BLMainSignals& getMainSignals() {
    return g_signals;
}

void RegisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.m_internals->UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1, _2, _3));
    g_signals.m_internals->TransactionAddedToMempool.connect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, _1));
    g_signals.m_internals->BlockConnected.connect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, _1, _2, _3));
    g_signals.m_internals->BlockDisconnected.connect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, _1));
    g_signals.m_internals->setBestChain.connect(boost::bind(&CValidationInterface::setBestChain, pwalletIn, _1));
    g_signals.m_internals->Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.m_internals->Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.m_internals->BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.m_internals->NewPoWValidBlock.connect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, _1, _2));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn) {
    g_signals.m_internals->BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.m_internals->Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.m_internals->Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.m_internals->setBestChain.disconnect(boost::bind(&CValidationInterface::setBestChain, pwalletIn, _1));
    g_signals.m_internals->TransactionAddedToMempool.disconnect(boost::bind(&CValidationInterface::TransactionAddedToMempool, pwalletIn, _1));
    g_signals.m_internals->BlockConnected.disconnect(boost::bind(&CValidationInterface::BlockConnected, pwalletIn, _1, _2, _3));
    g_signals.m_internals->BlockDisconnected.disconnect(boost::bind(&CValidationInterface::BlockDisconnected, pwalletIn, _1));
    g_signals.m_internals->UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1, _2, _3));
    g_signals.m_internals->NewPoWValidBlock.disconnect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, _1, _2));
}

void UnregisterAllValidationInterfaces() {
    g_signals.m_internals->BlockChecked.disconnect_all_slots();
    g_signals.m_internals->Broadcast.disconnect_all_slots();
    g_signals.m_internals->Inventory.disconnect_all_slots();
    g_signals.m_internals->setBestChain.disconnect_all_slots();
    g_signals.m_internals->TransactionAddedToMempool.disconnect_all_slots();
    g_signals.m_internals->BlockConnected.disconnect_all_slots();
    g_signals.m_internals->BlockDisconnected.disconnect_all_slots();
    g_signals.m_internals->UpdatedBlockTip.disconnect_all_slots();
    g_signals.m_internals->NewPoWValidBlock.disconnect_all_slots();
}

void BLMainSignals::UpdatedBlockTip(const BLBlockIndex *pidxNew, const BLBlockIndex *pidxFork, bool fInitialDownload) {
    m_internals->UpdatedBlockTip(pidxNew, pidxFork, fInitialDownload);
}

void BLMainSignals::TransactionAddedToMempool(const CTransactionRef &ptx) {
    m_internals->TransactionAddedToMempool(ptx);
}

void BLMainSignals::BlockConnected(const std::shared_ptr<const BLBlock> &pblock, const BLBlockIndex *pidx, const std::vector<CTransactionRef>& vtxConflicted) {
    m_internals->BlockConnected(pblock, pidx, vtxConflicted);
}

void BLMainSignals::BlockDisconnected(const std::shared_ptr<const BLBlock> &pblock) {
    m_internals->BlockDisconnected(pblock);
}

void BLMainSignals::setBestChain(const BLBlockLocator &locator) {
    m_internals->setBestChain(locator);
}

void BLMainSignals::Inventory(const uint256 &hash) {
    m_internals->Inventory(hash);
}

void BLMainSignals::Broadcast(int64_t nBestBlockTime, CConnman* connman) {
    m_internals->Broadcast(nBestBlockTime, connman);
}

void BLMainSignals::BlockChecked(const BLBlock& block, const CValidationState& state) {
    m_internals->BlockChecked(block, state);
}

void BLMainSignals::NewPoWValidBlock(const BLBlockIndex *pidx, const std::shared_ptr<const BLBlock> &block) {
    m_internals->NewPoWValidBlock(pidx, block);
}
