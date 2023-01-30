// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DEPLOYMENTINFO_H
#define BITCOIN_DEPLOYMENTINFO_H

#include <consensus/params.h>

#include <map>
#include <string>

/** What bits to set to signal activation */
static constexpr int32_t VERSIONBITS_TOP_ACTIVE = 0x60000000UL;
/** What bits to set to signal abandonment */
static constexpr int32_t VERSIONBITS_TOP_ABANDON = 0x40000000UL;


struct VBDeploymentInfo {
    /** Deployment name */
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    bool gbt_force;
};

extern const VBDeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS];

std::string DeploymentName(Consensus::BuriedDeployment dep);

inline std::string DeploymentName(Consensus::DeploymentPos pos)
{
    assert(Consensus::ValidDeployment(pos));
    return VersionBitsDeploymentInfo[pos].name;
}

extern const std::map<std::string, uint32_t> g_verify_flag_names;

std::string FormatScriptFlags(uint32_t flags);

inline int32_t CalculateActivateVersion(uint16_t bip, uint8_t bip_version)
{
    return (VERSIONBITS_TOP_ACTIVE | (int32_t{bip} << 8) | bip_version);
}

inline int32_t CalculateAbandonVersion(int bip, int bip_version)
{
    return (VERSIONBITS_TOP_ABANDON | (int32_t{bip} << 8) | bip_version);
}

#endif // BITCOIN_DEPLOYMENTINFO_H
