// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_REQUEST_H
#define BITCOIN_RPC_REQUEST_H

#include <any>
#include <optional>
#include <string>

#include <univalue.h>

enum class JSONVersion {
    JSON_1_BTC,
    JSON_2_0
};

UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id);
UniValue JSONRPCReplyObj(UniValue result, UniValue error, std::optional<UniValue> id, JSONVersion json_version);
UniValue JSONRPCError(int code, const std::string& message);

/** Generate a new RPC authentication cookie and write it to disk */
bool GenerateAuthCookie(std::string *cookie_out);
/** Read the RPC authentication cookie from disk */
bool GetAuthCookie(std::string *cookie_out);
/** Delete RPC authentication cookie from disk */
void DeleteAuthCookie();
/** Parse JSON-RPC batch reply into a vector */
std::vector<UniValue> JSONRPCProcessBatchReply(const UniValue& in);

class JSONRPCRequest
{
public:
    std::optional<UniValue> id = UniValue::VNULL;
    std::string strMethod;
    UniValue params;
    enum Mode { EXECUTE, GET_HELP, GET_ARGS } mode = EXECUTE;
    std::string URI;
    std::string authUser;
    std::string peerAddr;
    std::any context;
    JSONVersion m_json_version = JSONVersion::JSON_1_BTC;

    void parse(const UniValue& valRequest);
    [[nodiscard]] bool IsNotification() const { return !id.has_value() && m_json_version == JSONVersion::JSON_2_0; };
};

#endif // BITCOIN_RPC_REQUEST_H
