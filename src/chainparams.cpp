// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 The MANO Coin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 31968473 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "06/04/18 Bitcoin.com Taiwanese Miner Shot for Debt to Investors";
    const CScript genesisOutputScript = CScript() << ParseHex("043fc32e5547f16a9710d76fa543776c886fcec7fc52dff72a6c8072c132ae6aba33099e515c2ebdc7d8a1cc0adb5c26dc6c420b86d87d1fa2be0cfadfa5e6c990") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 255500; // Block rewards are cut in half every 255500 blocks (about 1 year)
        consensus.nMasternodePaymentsStartBlock = 65; // 65 blocks
        consensus.nMasternodePaymentsIncreaseBlock = 95; // 95 blocks
        consensus.nMasternodePaymentsIncreasePeriod = 30; // ~60 mins in blocks
        consensus.nInstantSendKeepLock = 24;
        consensus.nBudgetPaymentsStartBlock = 255500; // one year from now
        consensus.nBudgetPaymentsCycleBlocks = 21000; // ~(60*24*30)/2, actual number of blocks per month is 255500 / 12 = 21291
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 60*60*24;
        consensus.nSuperblockStartBlock = 276500; // one year and 1 month from now
        consensus.nSuperblockCycle = 21000; // ~(60*24*30)/2, actual number of blocks per month is 255500 / 12 = 21291
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x00000b268c07975f407c81ea67e8a83295b292b1c740e671d8e03c20aaf7a33e"); // 0
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // MANO: 1 day
        consensus.nPowTargetSpacing = 2 * 60; // MANO: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1528088503; // Monday, June 4, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout =  1536033600; // September 4, 2018 4:00:00 AM

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1528088503; // Monday, June 4, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1543939200; //December 4, 2018 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 4032;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 3226; // 80% of 4032

        // The best chain should have at least this much work.
       consensus.nMinimumChainWork = uint256S("00000000000000000000000000000000000000000000000000606db762cc19d7"); // 9517

        // By default assume that the signatures in ancestors of this block are valid.
       consensus.defaultAssumeValid = uint256S("0x000000000019f388b70c39e87931b05e9fd0c381c9f2f7112211af16c4075987"); // 9517

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc4;
        pchMessageStart[1] = 0xfb;
        pchMessageStart[2] = 0xde;
        pchMessageStart[3] = 0xb0;
        vAlertPubKey = ParseHex("0420b24423eb082341dfa41df37ca6a3cc3153416bf6bb58b4d5c0532f08ba84e29f056caeeee4c9cd443c68a14114704089dbbb5efd21f98eaed7ca2ba349e5d9");
        nDefaultPort = 5982;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nDelayGetHeadersTime = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1528088503, 1839581, 0x1e0ffff0, 1, 10 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x00000b268c07975f407c81ea67e8a83295b292b1c740e671d8e03c20aaf7a33e"));
        assert(genesis.hashMerkleRoot == uint256S("0x23cb8d05e3c20de367bfddd4bb582a84ac77dd26c2fd679e221dc704017ef3e9"));


        vSeeds.push_back(CDNSSeedData("167.179.94.218", "167.179.94.218" ));
        vSeeds.push_back(CDNSSeedData("45.76.213.173", "45.76.213.173" ));
        vSeeds.push_back(CDNSSeedData("202.182.101.132", "202.182.101.132" ));


        // MANO addresses start with 'M'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,50); // M
        // MANO script addresses start with 'S'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63); // S
        // MANO private keys
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,80);
        // MANO BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // MANO BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        // MANO BIP44 coin type is '5'
        nExtCoinType = 5;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour
        strSporkPubKey = "04779207612160e91c4d2739cfecc0dfeb2cf18c7788be9edfe4fc50ada9be93551c9be432e3c696a5f67b91c349ea1482dd222015cd27fcc674fd96715daee0ad";

        /**
         * What makes a good checkpoint block?
         * + Is surrounded by blocks with reasonable timestamps
         *   (no blocks before with a timestamp after, none after with
         *    timestamp before)
         * + Contains no strange transactions
         */

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
           (  7, uint256S("0x00000dfd045fad7bdbb28512ce804d452945547e0510644bbbecb466b4cf92f5"))
           ( 10, uint256S("0x0000086544ae58ca1f6d82d0a734e7959e8ed73a844ce762af22fe741c583552"))
           ( 9517, uint256S("0x000000000019f388b70c39e87931b05e9fd0c381c9f2f7112211af16c4075987")),
            1529304311, // * UNIX timestamp of last checkpoint block
            4008,    // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            250        // * estimated number of transactions per day after checkpoint
       };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 255500;
        consensus.nMasternodePaymentsStartBlock = 5; // not true, but it's ok as long as it's less then nMasternodePaymentsIncreaseBlock
        consensus.nMasternodePaymentsIncreaseBlock = 15;
        consensus.nMasternodePaymentsIncreasePeriod = 20;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 200;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 250; // NOTE: Should satisfy nSuperblockStartBlock > nBudgetPeymentsStartBlock
        consensus.nSuperblockCycle = 24; // Superblocks can be issued hourly on testnet
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 500;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0000057453b4b8889d218a7a9264eb21e955757340205eaadedabba221d3e3f0");
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // MANO: 1 day
        consensus.nPowTargetSpacing = 2 * 60; // MANO: 2 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1528088503; //June 4, 2018
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout =  1536033600; // September 4, 2018 4:00:00 AM

        // Deployment of DIP0001
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 1528088503; // June 4, 2018 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 1543939200; //December 4, 2018 4:00:00 PM
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nWindowSize = 100;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nThreshold = 50; // 50% of 100

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000600015"); // 5

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000653cbaf56c325836086943793b3afd3cf0824d7d758b831f06d7cf49ce1"); // 5

        pchMessageStart[0] = 0xe5;
        pchMessageStart[1] = 0xb2;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xe5;
        vAlertPubKey = ParseHex("0420b24423eb082341dfa41df37ca6a3cc3153416bf6bb58b4d5c0532f08ba84e29f056caeeee4c9cd443c68a14114704089dbbb5efd21f98eaed7ca2ba349e5d9");
        nDefaultPort = 15982;
        nMaxTipAge = 0x7fffffff; // allow mining on top of old blocks for testnet
        nDelayGetHeadersTime = 24 * 60 * 60;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1517437023, 1038198, 0x1e0ffff0, 1, 10 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0000057453b4b8889d218a7a9264eb21e955757340205eaadedabba221d3e3f0"));
        assert(genesis.hashMerkleRoot == uint256S("0x23cb8d05e3c20de367bfddd4bb582a84ac77dd26c2fd679e221dc704017ef3e9"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("mano.org", "tseed.mano.org" ));

        // Testnet MANO addresses start with 'c'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,110); // m
        // Testnet MANO script addresses start with 's'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125); // s
        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Testnet MANO BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet MANO BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Testnet MANO BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 3;
        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes
        strSporkPubKey = "044554383c929e5543784e83fef24e03df973c9342260464521aa4555716392473591b7ffff831f4bbf45e7a843ab6041dbd57aa6844ef564071a337e1b19f0f33";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (   5, uint256S("0x00000653cbaf56c325836086943793b3afd3cf0824d7d758b831f06d7cf49ce1")),

            1528097127, // * UNIX timestamp of last checkpoint block
            0,       // * total number of transactions between genesis and last checkpoint
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.01         // * estimated number of transactions per day after checkpoint
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMasternodePaymentsStartBlock = 20;
        consensus.nMasternodePaymentsIncreaseBlock = 35;
        consensus.nMasternodePaymentsIncreasePeriod = 10;
        consensus.nInstantSendKeepLock = 6;
        consensus.nBudgetPaymentsStartBlock = 1000;
        consensus.nBudgetPaymentsCycleBlocks = 50;
        consensus.nBudgetPaymentsWindowBlocks = 10;
        consensus.nBudgetProposalEstablishingTime = 60*20;
        consensus.nSuperblockStartBlock = 1500;
        consensus.nSuperblockCycle = 10;
        consensus.nGovernanceMinQuorum = 1;
        consensus.nGovernanceFilterElements = 100;
        consensus.nMasternodeMinimumConfirmations = 1;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 24 * 60 * 60; // MANO: 1 day
        consensus.nPowTargetSpacing = 2.5 * 60; // MANO: 2.5 minutes
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_DIP0001].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xe6;
        pchMessageStart[1] = 0xc5;
        pchMessageStart[2] = 0xa3;
        pchMessageStart[3] = 0xf2;
        nMaxTipAge = 6 * 60 * 60; // ~144 blocks behind -> 2 x fork detection time, was 24 * 60 * 60 in bitcoin
        nDelayGetHeadersTime = 0; // never delay GETHEADERS in regtests
        nDefaultPort = 25982;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1528088503, 1, 0x207fffff, 1, 10 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

          assert(consensus.hashGenesisBlock == uint256S("0x305a859f6f761609cc723461dce07a47ea1ed631f4212f6a38d938aa318d5c79"));
          assert(genesis.hashMerkleRoot == uint256S("0x23cb8d05e3c20de367bfddd4bb582a84ac77dd26c2fd679e221dc704017ef3e9"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        nFulfilledRequestExpireTime = 5*60; // fulfilled requests expire in 5 minutes

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x00")),
            0,
            0,
            0
        };
        // Regtest MANO addresses start with 'y'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        // Regtest MANO script addresses start with '8' or '9'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        // Regtest private keys start with '9' or 'c' (Bitcoin defaults)
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        // Regtest MANO BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Regtest MANO BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        // Regtest MANO BIP44 coin type is '1' (All coin's testnet default)
        nExtCoinType = 1;
   }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}
