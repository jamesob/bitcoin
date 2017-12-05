// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <capnp/blob.h>
#include <capnp/common.h>
#include <capnp/list.h>
#include <ipc/capnp/common-types.h>
#include <ipc/capnp/common.capnp.h>
#include <ipc/capnp/common.capnp.proxy-types.h>
#include <ipc/capnp/common.h>
#include <ipc/capnp/context.h>
#include <mp/proxy-io.h>
#include <mp/proxy-types.h>
#include <mp/util.h>
#include <sync.h>
#include <univalue.h>
#include <util/settings.h>
#include <util/system.h>

#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace ipc {
namespace capnp {
void BuildGlobalArgs(mp::InvokeContext& invoke_context, messages::GlobalArgs::Builder&& builder)
{
    gArgs.LockSettings([&](const util::Settings& settings) {
        mp::BuildField(mp::TypeList<util::Settings>(), invoke_context,
                       mp::Make<mp::ValueField>(builder.initSettings()), settings);
    });
}

void ReadGlobalArgs(mp::InvokeContext& invoke_context, const messages::GlobalArgs::Reader& reader)
{
    gArgs.LockSettings([&](util::Settings& settings) {
        mp::ReadField(mp::TypeList<util::Settings>(), invoke_context, mp::Make<mp::ValueField>(reader.getSettings()),
                      mp::ReadDestValue(settings));
    });
    SelectParams(gArgs.GetChainName());
}
} // namespace capnp
} // namespace ipc
