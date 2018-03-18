// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Wizbl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wizbl/blockchain/chainparamsbase.h"

#include "wizbl/blockchain/util/tinyformat.h"
#include "wizbl/blockchain/util/util.h"

#include <assert.h>

const std::string BLBaseChainParams::MAIN = "main";
const std::string BLBaseChainParams::TESTNET = "test";
const std::string BLBaseChainParams::REGTEST = "regtest";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp) {
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test chain"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
    }
}

/**
 * Main network
 */
class BLBaseMainParams : public BLBaseChainParams {
public:
    BLBaseMainParams() {
        nRPCPort = 8332;
    }
};

/**
 * Testnet (v3)
 */
class BLBaseTestNetParams : public BLBaseChainParams {
public:
    BLBaseTestNetParams() {
        nRPCPort = 18332;
        strDataDir = "testnet3";
    }
};

/*
 * Regression test
 */
class BLBaseRegTestParams : public BLBaseChainParams {
public:
    BLBaseRegTestParams() {
        nRPCPort = 18332;
        strDataDir = "regtest";
    }
};

static std::unique_ptr<BLBaseChainParams> globalChainBaseParams;

const BLBaseChainParams& BaseParams() {
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

std::unique_ptr<BLBaseChainParams> CreateBaseChainParams(const std::string& chain) {
    if (chain == BLBaseChainParams::MAIN)
        return std::unique_ptr<BLBaseChainParams>(new BLBaseMainParams());
    else if (chain == BLBaseChainParams::TESTNET)
        return std::unique_ptr<BLBaseChainParams>(new BLBaseTestNetParams());
    else if (chain == BLBaseChainParams::REGTEST)
        return std::unique_ptr<BLBaseChainParams>(new BLBaseRegTestParams());
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain) {
    globalChainBaseParams = CreateBaseChainParams(chain);
}

std::string ChainNameFromCommandLine() {
    bool fRegTest = gArgs.getBoolArg("-regtest", false);
    bool fTestNet = gArgs.getBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (fRegTest)
        return BLBaseChainParams::REGTEST;
    if (fTestNet)
        return BLBaseChainParams::TESTNET;
    return BLBaseChainParams::MAIN;
}
