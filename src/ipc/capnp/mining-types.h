// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_IPC_CAPNP_MINING_TYPES_H
#define BITCOIN_IPC_CAPNP_MINING_TYPES_H

#include <interfaces/mining.h>
#include <ipc/capnp/common.capnp.proxy-types.h>
#include <ipc/capnp/common-types.h>
#include <ipc/capnp/mining.capnp.proxy.h>
#include <node/miner.h>
#include <node/types.h>
#include <validation.h>

namespace mp {
// Custom serialization for BlockValidationState.
void CustomBuildMessage(InvokeContext& invoke_context,
                        const BlockValidationState& src,
                        ipc::capnp::messages::BlockValidationState::Builder&& builder);
void CustomReadMessage(InvokeContext& invoke_context,
                       const ipc::capnp::messages::BlockValidationState::Reader& reader,
                       BlockValidationState& dest);

// Custom serialization for int argc, char** argv arguments.
template <typename Argc, typename Argv, typename Output>
void CustomBuildField(TypeList<int, const char* const*>, Priority<1>, InvokeContext& invoke_context, Argc&& argc, Argv&& argv, Output&& output)
{
    capnp::List<capnp::Text>::Builder args{output.init(argc)};
    for (int i = 0; i < argc; ++i) {
        args.set(i, argv[i]);
    }
}

template <typename Accessor, typename ServerContext, typename Fn, typename... Args>
auto CustomPassField(TypeList<int, const char* const*>, ServerContext& server_context, const Fn& fn, Args&&... args)
{
    const auto& params = server_context.call_context.getParams();
    const auto& input = Make<StructField, Accessor>(params);
    capnp::List<capnp::Text>::Reader argv = input.get();
    std::vector<const char*> vec;
    vec.reserve(argv.size());
    for (auto arg : argv) {
        vec.push_back(arg.cStr());
    }
    return fn.invoke(server_context, std::forward<Args>(args)..., argv.size(), vec.data());
}
} // namespace mp

#endif // BITCOIN_IPC_CAPNP_MINING_TYPES_H
