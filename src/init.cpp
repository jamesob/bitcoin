// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <init.h>

#include <init_settings.h>
#include <kernel/checks.h>

#include <addrman.h>
#include <banman.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <deploymentstatus.h>
#include <hash.h>
#include <httprpc.h>
#include <httpserver.h>
#include <index/blockfilterindex.h>
#include <index/coinstatsindex.h>
#include <index/txindex.h>
#include <init/common.h>
#include <interfaces/chain.h>
#include <interfaces/init.h>
#include <interfaces/ipc.h>
#include <interfaces/mining.h>
#include <interfaces/node.h>
#include <kernel/context.h>
#include <key.h>
#include <logging.h>
#include <mapport.h>
#include <net.h>
#include <net_permissions.h>
#include <net_processing.h>
#include <netbase.h>
#include <netgroup.h>
#include <node/blockmanager_args.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/chainstate.h>
#include <node/chainstatemanager_args.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <node/kernel_notifications.h>
#include <node/mempool_args.h>
#include <node/mempool_persist.h>
#include <node/mempool_persist_args.h>
#include <node/miner.h>
#include <node/peerman_args.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/fees_args.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <protocol.h>
#include <rpc/blockchain.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <scheduler.h>
#include <script/sigcache.h>
#include <sync.h>
#include <torcontrol.h>
#include <txdb.h>
#include <txmempool.h>
#include <util/asmap.h>
#include <util/batchpriority.h>
#include <util/chaintype.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/moneystr.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/syserror.h>
#include <util/thread.h>
#include <util/threadnames.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <walletinitinterface.h>

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <functional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifndef WIN32
#include <cerrno>
#include <signal.h>
#include <sys/stat.h>
#endif

#include <boost/signals2/signal.hpp>

#ifdef ENABLE_ZMQ
#include <zmq/zmqabstractnotifier.h>
#include <zmq/zmqnotificationinterface.h>
#include <zmq/zmqrpc.h>
#endif

using common::AmountErrMsg;
using common::InvalidPortErrMsg;
using common::ResolveErrMsg;

using node::ApplyArgsManOptions;
using node::BlockManager;
using node::CacheSizes;
using node::CalculateCacheSizes;
using node::ChainstateLoadResult;
using node::ChainstateLoadStatus;
using node::DumpMempool;
using node::ImportBlocks;
using node::KernelNotifications;
using node::LoadChainstate;
using node::LoadMempool;
using node::MempoolPath;
using node::NodeContext;
using node::ShouldPersistMempool;
using node::VerifyLoadedChainstate;
using util::ReplaceAll;
using util::ToString;

#ifdef WIN32
// Win32 LevelDB doesn't use filedescriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_LEVELDB_FDS 0
#else
#define MIN_LEVELDB_FDS 150
#endif

static constexpr int MIN_CORE_FDS = MIN_LEVELDB_FDS + NUM_FDS_MESSAGE_CAPTURE;

/**
 * The PID file facilities.
 */
/**
 * True if this process has created a PID file.
 * Used to determine whether we should remove the PID file on shutdown.
 */
static bool g_generated_pid{false};

static fs::path GetPidFile(const ArgsManager& args)
{
    return AbsPathForConfigVal(args, PidSetting::Get(args));
}

[[nodiscard]] static bool CreatePidFile(const ArgsManager& args)
{
    if (PidSetting::Value(args).isFalse()) return true;

    std::ofstream file{GetPidFile(args)};
    if (file) {
#ifdef WIN32
        tfm::format(file, "%d\n", GetCurrentProcessId());
#else
        tfm::format(file, "%d\n", getpid());
#endif
        g_generated_pid = true;
        return true;
    } else {
        return InitError(strprintf(_("Unable to create the PID file '%s': %s"), fs::PathToString(GetPidFile(args)), SysErrorString(errno)));
    }
}

static void RemovePidFile(const ArgsManager& args)
{
    if (!g_generated_pid) return;
    const auto pid_path{GetPidFile(args)};
    if (std::error_code error; !fs::remove(pid_path, error)) {
        std::string msg{error ? error.message() : "File does not exist"};
        LogPrintf("Unable to remove PID file (%s): %s\n", fs::PathToString(pid_path), msg);
    }
}

static std::optional<util::SignalInterrupt> g_shutdown;

void InitContext(NodeContext& node)
{
    assert(!g_shutdown);
    g_shutdown.emplace();

    node.args = &gArgs;
    node.shutdown_signal = &*g_shutdown;
    node.shutdown_request = [&node] {
        assert(node.shutdown_signal);
        if (!(*node.shutdown_signal)()) return false;
        // Wake any threads that may be waiting for the tip to change.
        if (node.notifications) WITH_LOCK(node.notifications->m_tip_block_mutex, node.notifications->m_tip_block_cv.notify_all());
        return true;
    };
}

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit() or the Qt main() function.
//
// A clean exit happens when the SignalInterrupt object is triggered, which
// makes the main thread's SignalInterrupt::wait() call return, and join all
// other ongoing threads in the thread group to the main thread.
// Shutdown() is then called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Shutdown for Qt is very similar, only it uses a QTimer to detect
// ShutdownRequested() getting set, and then does the normal Qt
// shutdown thing.
//

bool ShutdownRequested(node::NodeContext& node)
{
    return bool{*Assert(node.shutdown_signal)};
}

#if HAVE_SYSTEM
static void ShutdownNotify(const ArgsManager& args)
{
    std::vector<std::thread> threads;
    for (const auto& cmd : ShutdownnotifySetting::Get(args)) {
        threads.emplace_back(runCommand, cmd);
    }
    for (auto& t : threads) {
        t.join();
    }
}
#endif

void Interrupt(NodeContext& node)
{
#if HAVE_SYSTEM
    ShutdownNotify(*node.args);
#endif
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    InterruptMapPort();
    if (node.connman)
        node.connman->Interrupt();
    for (auto* index : node.indexes) {
        index->Interrupt();
    }
}

void Shutdown(NodeContext& node)
{
    static Mutex g_shutdown_mutex;
    TRY_LOCK(g_shutdown_mutex, lock_shutdown);
    if (!lock_shutdown) return;
    LogPrintf("%s: In progress...\n", __func__);
    Assert(node.args);

    /// Note: Shutdown() must be able to handle cases in which initialization failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    util::ThreadRename("shutoff");
    if (node.mempool) node.mempool->AddTransactionsUpdated(1);

    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();
    for (const auto& client : node.chain_clients) {
        client->flush();
    }
    StopMapPort();

    // Because these depend on each-other, we make sure that neither can be
    // using the other before destroying them.
    if (node.peerman && node.validation_signals) node.validation_signals->UnregisterValidationInterface(node.peerman.get());
    if (node.connman) node.connman->Stop();

    StopTorControl();

    if (node.background_init_thread.joinable()) node.background_init_thread.join();
    // After everything has been shut down, but before things get flushed, stop the
    // the scheduler. After this point, SyncWithValidationInterfaceQueue() should not be called anymore
    // as this would prevent the shutdown from completing.
    if (node.scheduler) node.scheduler->stop();

    // After the threads that potentially access these pointers have been stopped,
    // destruct and reset all to nullptr.
    node.peerman.reset();
    node.connman.reset();
    node.banman.reset();
    node.addrman.reset();
    node.netgroupman.reset();

    if (node.mempool && node.mempool->GetLoadTried() && ShouldPersistMempool(*node.args)) {
        DumpMempool(*node.mempool, MempoolPath(*node.args));
    }

    // Drop transactions we were still watching, record fee estimations and unregister
    // fee estimator from validation interface.
    if (node.fee_estimator) {
        node.fee_estimator->Flush();
        if (node.validation_signals) {
            node.validation_signals->UnregisterValidationInterface(node.fee_estimator.get());
        }
    }

    // FlushStateToDisk generates a ChainStateFlushed callback, which we should avoid missing
    if (node.chainman) {
        LOCK(cs_main);
        for (Chainstate* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
            }
        }
    }

    // After there are no more peers/RPC left to give us new data which may generate
    // CValidationInterface callbacks, flush them...
    if (node.validation_signals) node.validation_signals->FlushBackgroundCallbacks();

    // Stop and delete all indexes only after flushing background callbacks.
    for (auto* index : node.indexes) index->Stop();
    if (g_txindex) g_txindex.reset();
    if (g_coin_stats_index) g_coin_stats_index.reset();
    DestroyAllBlockFilterIndexes();
    node.indexes.clear(); // all instances are nullptr now

    // Any future callbacks will be dropped. This should absolutely be safe - if
    // missing a callback results in an unrecoverable situation, unclean shutdown
    // would too. The only reason to do the above flushes is to let the wallet catch
    // up with our current chain to avoid any strange pruning edge cases and make
    // next startup faster by avoiding rescan.

    if (node.chainman) {
        LOCK(cs_main);
        for (Chainstate* chainstate : node.chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }
    for (const auto& client : node.chain_clients) {
        client->stop();
    }

#ifdef ENABLE_ZMQ
    if (g_zmq_notification_interface) {
        if (node.validation_signals) node.validation_signals->UnregisterValidationInterface(g_zmq_notification_interface.get());
        g_zmq_notification_interface.reset();
    }
#endif

    node.chain_clients.clear();
    if (node.validation_signals) {
        node.validation_signals->UnregisterAllValidationInterfaces();
    }
    node.mempool.reset();
    node.fee_estimator.reset();
    node.chainman.reset();
    node.validation_signals.reset();
    node.scheduler.reset();
    node.ecc_context.reset();
    node.kernel.reset();

    RemovePidFile(*node.args);

    LogPrintf("%s: done\n", __func__);
}

/**
 * Signal handlers are very limited in what they are allowed to do.
 * The execution context the handler is invoked in is not guaranteed,
 * so we restrict handler operations to just touching variables:
 */
#ifndef WIN32
static void HandleSIGTERM(int)
{
    // Return value is intentionally ignored because there is not a better way
    // of handling this failure in a signal handler.
    (void)(*Assert(g_shutdown))();
}

static void HandleSIGHUP(int)
{
    LogInstance().m_reopen_file = true;
}
#else
static BOOL WINAPI consoleCtrlHandler(DWORD dwCtrlType)
{
    if (!(*Assert(g_shutdown))()) {
        LogError("Failed to send shutdown signal on Ctrl-C\n");
        return false;
    }
    Sleep(INFINITE);
    return true;
}
#endif

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}
#endif

void SetupServerArgs(ArgsManager& argsman, bool can_listen_ipc)
{
    SetupHelpOptions(argsman);
    HelpDebugSetting::Register(argsman); // server-only for now

    init::AddLoggingArgs(argsman);

    const auto defaultBaseParams = CreateBaseChainParams(ChainType::MAIN);
    const auto testnetBaseParams = CreateBaseChainParams(ChainType::TESTNET);
    const auto testnet4BaseParams = CreateBaseChainParams(ChainType::TESTNET4);
    const auto signetBaseParams = CreateBaseChainParams(ChainType::SIGNET);
    const auto regtestBaseParams = CreateBaseChainParams(ChainType::REGTEST);
    const auto defaultChainParams = CreateChainParams(argsman, ChainType::MAIN);
    const auto testnetChainParams = CreateChainParams(argsman, ChainType::TESTNET);
    const auto testnet4ChainParams = CreateChainParams(argsman, ChainType::TESTNET4);
    const auto signetChainParams = CreateChainParams(argsman, ChainType::SIGNET);
    const auto regtestChainParams = CreateChainParams(argsman, ChainType::REGTEST);

    // Hidden Options
    DbcrashratioSettingHidden::Register(argsman);
    ForcecompactdbSettingHidden::Register(argsman);
    // GUI args. These will be overwritten by SetupUIArgs for the GUI
    ChoosedatadirSettingHidden::Register(argsman);
    LangSettingHidden::Register(argsman);
    MinSettingHidden::Register(argsman);
    ResetguisettingsSettingHidden::Register(argsman);
    SplashSettingHidden::Register(argsman);
    UiplatformSettingHidden::Register(argsman);

    VersionSetting::Register(argsman);
#if HAVE_SYSTEM
    AlertnotifySetting::Register(argsman);
#endif
    AssumevalidSetting::Register(argsman, defaultChainParams, testnetChainParams, testnet4ChainParams, signetChainParams);
    BlocksdirSetting::Register(argsman);
    BlocksxorSetting::Register(argsman);
    FastpruneSetting::Register(argsman);
#if HAVE_SYSTEM
    BlocknotifySetting::Register(argsman);
#endif
    BlockreconstructionextratxnSetting::Register(argsman);
    BlocksonlySetting::Register(argsman);
    CoinstatsindexSetting::Register(argsman);
    ConfSetting::Register(argsman);
    DatadirSetting::Register(argsman);
    DbbatchsizeSetting::Register(argsman);
    DbcacheSetting::Register(argsman);
    IncludeconfSetting::Register(argsman);
    AllowignoredconfSetting::Register(argsman);
    LoadblockSetting::Register(argsman);
    MaxmempoolSetting::Register(argsman);
    MaxorphantxSetting::Register(argsman);
    MempoolexpirySetting::Register(argsman);
    MinimumchainworkSetting::Register(argsman, defaultChainParams, testnetChainParams, testnet4ChainParams, signetChainParams);
    ParSetting::Register(argsman);
    PersistmempoolSetting::Register(argsman);
    Persistmempoolv1Setting::Register(argsman);
    PidSetting::Register(argsman);
    PruneSetting::Register(argsman);
    ReindexSetting::Register(argsman);
    ReindexChainstateSetting::Register(argsman);
    SettingsSetting::Register(argsman);
#if HAVE_SYSTEM
    StartupnotifySetting::Register(argsman);
    ShutdownnotifySetting::Register(argsman);
#endif
    TxindexSetting::Register(argsman);
    BlockfilterindexSetting::Register(argsman);

    AddnodeSetting::Register(argsman);
    AsmapSetting::Register(argsman);
    BantimeSetting::Register(argsman);
    BindSetting::Register(argsman, defaultBaseParams, testnetBaseParams, testnet4BaseParams, signetBaseParams, regtestBaseParams);
    CjdnsreachableSetting::Register(argsman);
    ConnectSetting::Register(argsman);
    DiscoverSetting::Register(argsman);
    DnsSetting::Register(argsman);
    DnsseedSetting::Register(argsman);
    ExternalipSetting::Register(argsman);
    FixedseedsSetting::Register(argsman);
    ForcednsseedSetting::Register(argsman);
    ListenSetting::Register(argsman);
    ListenonionSetting::Register(argsman);
    MaxconnectionsSetting::Register(argsman);
    MaxreceivebufferSetting::Register(argsman);
    MaxsendbufferSetting::Register(argsman);
    MaxuploadtargetSetting::Register(argsman);
#ifdef HAVE_SOCKADDR_UN
    OnionSetting::Register(argsman);
#else
    OnionSetting2::Register(argsman);
#endif
    I2psamSetting::Register(argsman);
    I2pacceptincomingSetting::Register(argsman);
    OnlynetSetting::Register(argsman);
    V2transportSetting::Register(argsman);
    PeerbloomfiltersSetting::Register(argsman);
    PeerblockfiltersSetting::Register(argsman);
    TxreconciliationSetting::Register(argsman);
    PortSetting::Register(argsman, defaultChainParams, testnetChainParams, testnet4ChainParams, signetChainParams, regtestChainParams);
#ifdef HAVE_SOCKADDR_UN
    ProxySetting::Register(argsman);
#else
    ProxySetting2::Register(argsman);
#endif
    ProxyrandomizeSetting::Register(argsman);
    SeednodeSetting::Register(argsman);
    NetworkactiveSetting::Register(argsman);
    TimeoutSetting::Register(argsman);
    PeertimeoutSetting::Register(argsman);
    TorcontrolSetting::Register(argsman);
    TorpasswordSetting::Register(argsman);
    // UPnP support was dropped. We keep `-upnp` as a hidden arg to display a more user friendly error when set. TODO: remove (here and below) for 30.0. NOTE: removing this option may prevent the GUI from starting, see https://github.com/bitcoin-core/gui/issues/843.
    UpnpSetting::Register(argsman);
    NatpmpSetting::Register(argsman);
    WhitebindSetting::Register(argsman);

    WhitelistSetting::Register(argsman);

    g_wallet_init_interface.AddWalletOptions(argsman);

#ifdef ENABLE_ZMQ
    ZmqpubhashblockSetting::Register(argsman);
    ZmqpubhashtxSetting::Register(argsman);
    ZmqpubrawblockSetting::Register(argsman);
    ZmqpubrawtxSetting::Register(argsman);
    ZmqpubsequenceSetting::Register(argsman);
    ZmqpubhashblockhwmSetting::Register(argsman);
    ZmqpubhashtxhwmSetting::Register(argsman);
    ZmqpubrawblockhwmSetting::Register(argsman);
    ZmqpubrawtxhwmSetting::Register(argsman);
    ZmqpubsequencehwmSetting::Register(argsman);
#else
    ZmqpubhashblockSetting::Hidden::Register(argsman);
    ZmqpubhashtxSetting::Hidden::Register(argsman);
    ZmqpubrawblockSetting::Hidden::Register(argsman);
    ZmqpubrawtxSetting::Hidden::Register(argsman);
    ZmqpubsequenceSetting::Hidden::Register(argsman);
    ZmqpubhashblockhwmSetting::Hidden::Register(argsman);
    ZmqpubhashtxhwmSetting::Hidden::Register(argsman);
    ZmqpubrawblockhwmSetting::Hidden::Register(argsman);
    ZmqpubrawtxhwmSetting::Hidden::Register(argsman);
    ZmqpubsequencehwmSetting::Hidden::Register(argsman);
#endif

    CheckblocksSetting::Register(argsman);
    ChecklevelSetting::Register(argsman);
    CheckblockindexSetting::Register(argsman, defaultChainParams, regtestChainParams);
    CheckaddrmanSetting::Register(argsman);
    CheckmempoolSetting::Register(argsman, defaultChainParams, regtestChainParams);
    CheckpointsSetting::Register(argsman, defaultChainParams);
    DeprecatedrpcSetting::Register(argsman);
    StopafterblockimportSetting::Register(argsman);
    StopatheightSetting::Register(argsman);
    LimitancestorcountSetting::Register(argsman);
    LimitancestorsizeSetting::Register(argsman);
    LimitdescendantcountSetting::Register(argsman);
    LimitdescendantsizeSetting::Register(argsman);
    TestSetting::Register(argsman);
    CapturemessagesSetting::Register(argsman);
    MocktimeSetting::Register(argsman);
    MaxsigcachesizeSetting::Register(argsman);
    MaxtipageSetting::Register(argsman);
    PrintprioritySetting::Register(argsman);
    UacommentSetting::Register(argsman);

    SetupChainParamsBaseOptions(argsman);

    AcceptnonstdtxnSetting::Register(argsman);
    IncrementalrelayfeeSetting::Register(argsman);
    DustrelayfeeSetting::Register(argsman);
    AcceptstalefeeestimatesSetting::Register(argsman);
    BytespersigopSetting::Register(argsman);
    DatacarrierSetting::Register(argsman);
    DatacarriersizeSetting::Register(argsman);
    PermitbaremultisigSetting::Register(argsman);
    MinrelaytxfeeSetting::Register(argsman);
    WhitelistforcerelaySetting::Register(argsman);
    WhitelistrelaySetting::Register(argsman);


    BlockmaxweightSetting::Register(argsman);
    BlockmintxfeeSetting::Register(argsman);
    BlockversionSetting::Register(argsman);

    RestSetting::Register(argsman);
    RpcallowipSetting::Register(argsman);
    RpcauthSetting::Register(argsman);
    RpcbindSetting::Register(argsman);
    RpcdoccheckSetting::Register(argsman);
    RpccookiefileSetting::Register(argsman);
    RpccookiepermsSetting::Register(argsman);
    RpcpasswordSetting::Register(argsman);
    RpcportSetting::Register(argsman, defaultBaseParams, testnetBaseParams, testnet4BaseParams, signetBaseParams, regtestBaseParams);
    RpcservertimeoutSetting::Register(argsman);
    RpcthreadsSetting::Register(argsman);
    RpcuserSetting::Register(argsman);
    RpcwhitelistSetting::Register(argsman);
    RpcwhitelistdefaultSetting::Register(argsman);
    RpcworkqueueSetting::Register(argsman);
    ServerSetting::Register(argsman);
    if (can_listen_ipc) {
        IpcbindSetting::Register(argsman);
    }

#if HAVE_DECL_FORK
    DaemonSetting::Register(argsman);
    DaemonwaitSetting::Register(argsman);
#else
    DaemonSetting::Hidden::Register(argsman);
    DaemonwaitSetting::Hidden::Register(argsman);
#endif
}

#if HAVE_SYSTEM
static void StartupNotify(const ArgsManager& args)
{
    std::string cmd = StartupnotifySetting::Get(args);
    if (!cmd.empty()) {
        std::thread t(runCommand, cmd);
        t.detach(); // thread runs free
    }
}
#endif

static bool AppInitServers(NodeContext& node)
{
    const ArgsManager& args = *Assert(node.args);
    if (!InitHTTPServer(*Assert(node.shutdown_signal))) {
        return false;
    }
    StartRPC();
    node.rpc_interruption_point = RpcInterruptionPoint;
    if (!StartHTTPRPC(&node))
        return false;
    if (RestSetting::Get(args)) StartREST(&node);
    StartHTTPServer();
    return true;
}

// Parameter interaction based on rules
void InitParameterInteraction(ArgsManager& args)
{
    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (!BindSetting::Value(args).isNull()) {
        if (args.SoftSetBoolArg("-listen", true))
            LogInfo("parameter interaction: -bind set -> setting -listen=1\n");
    }
    if (!WhitebindSetting::Value(args).isNull()) {
        if (args.SoftSetBoolArg("-listen", true))
            LogInfo("parameter interaction: -whitebind set -> setting -listen=1\n");
    }

    if (!ConnectSetting::Value(args).isNull() || MaxconnectionsSetting::Get(args) <= 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (args.SoftSetBoolArg("-dnsseed", false))
            LogInfo("parameter interaction: -connect or -maxconnections=0 set -> setting -dnsseed=0\n");
        if (args.SoftSetBoolArg("-listen", false))
            LogInfo("parameter interaction: -connect or -maxconnections=0 set -> setting -listen=0\n");
    }

    std::string proxy_arg = ProxySetting::Get(args);
    if (proxy_arg != "" && proxy_arg != "0") {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (args.SoftSetBoolArg("-listen", false))
            LogInfo("parameter interaction: -proxy set -> setting -listen=0\n");
        // to protect privacy, do not map ports when a proxy is set. The user may still specify -listen=1
        // to listen locally, so don't rely on this happening through -listen below.
        if (args.SoftSetBoolArg("-natpmp", false)) {
            LogInfo("parameter interaction: -proxy set -> setting -natpmp=0\n");
        }
        // to protect privacy, do not discover addresses by default
        if (args.SoftSetBoolArg("-discover", false))
            LogInfo("parameter interaction: -proxy set -> setting -discover=0\n");
    }

    if (!ListenSetting::Get(args, DEFAULT_LISTEN)) {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        if (args.SoftSetBoolArg("-natpmp", false)) {
            LogInfo("parameter interaction: -listen=0 -> setting -natpmp=0\n");
        }
        if (args.SoftSetBoolArg("-discover", false))
            LogInfo("parameter interaction: -listen=0 -> setting -discover=0\n");
        if (args.SoftSetBoolArg("-listenonion", false))
            LogInfo("parameter interaction: -listen=0 -> setting -listenonion=0\n");
        if (args.SoftSetBoolArg("-i2pacceptincoming", false)) {
            LogInfo("parameter interaction: -listen=0 -> setting -i2pacceptincoming=0\n");
        }
    }

    if (!ExternalipSetting::Value(args).isNull()) {
        // if an explicit public IP is specified, do not try to find others
        if (args.SoftSetBoolArg("-discover", false))
            LogInfo("parameter interaction: -externalip set -> setting -discover=0\n");
    }

    if (BlocksonlySetting::Get(args, DEFAULT_BLOCKSONLY)) {
        // disable whitelistrelay in blocksonly mode
        if (args.SoftSetBoolArg("-whitelistrelay", false))
            LogInfo("parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n");
        // Reduce default mempool size in blocksonly mode to avoid unexpected resource usage
        if (args.SoftSetArg("-maxmempool", ToString(DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB)))
            LogInfo("parameter interaction: -blocksonly=1 -> setting -maxmempool=%d\n", DEFAULT_BLOCKSONLY_MAX_MEMPOOL_SIZE_MB);
    }

    // Forcing relay from whitelisted hosts implies we will accept relays from them in the first place.
    if (WhitelistforcerelaySetting::Get(args)) {
        if (args.SoftSetBoolArg("-whitelistrelay", true))
            LogInfo("parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n");
    }
    if (!OnlynetSetting::Value(args).isNull()) {
        const auto onlynets = OnlynetSetting::Get(args);
        bool clearnet_reachable = std::any_of(onlynets.begin(), onlynets.end(), [](const auto& net) {
            const auto n = ParseNetwork(net);
            return n == NET_IPV4 || n == NET_IPV6;
        });
        if (!clearnet_reachable && args.SoftSetBoolArg("-dnsseed", false)) {
            LogInfo("parameter interaction: -onlynet excludes IPv4 and IPv6 -> setting -dnsseed=0\n");
        }
    }
}

/**
 * Initialize global loggers.
 *
 * Note that this is called very early in the process lifetime, so you should be
 * careful about what global state you rely on here.
 */
void InitLogging(const ArgsManager& args)
{
    init::SetLoggingOptions(args);
    init::LogPackageVersion();
}

namespace { // Variables internal to initialization process only

int nMaxConnections;
int available_fds;
ServiceFlags g_local_services = ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS);
int64_t peer_connect_timeout;
std::set<BlockFilterType> g_enabled_filter_types;

} // namespace

[[noreturn]] static void new_handler_terminate()
{
    // Rather than throwing std::bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since logging may itself allocate memory, set the handler directly
    // to terminate first.
    std::set_new_handler(std::terminate);
    LogError("Out of memory. Terminating.\n");

    // The log was successful, terminate now.
    std::terminate();
};

bool AppInitBasicSetup(const ArgsManager& args, std::atomic<int>& exit_status)
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, 0));
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable heap terminate-on-corruption
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
#endif
    if (!SetupNetworking()) {
        return InitError(Untranslated("Initializing networking failed."));
    }

#ifndef WIN32
    // Clean shutdown on SIGTERM
    registerSignalHandler(SIGTERM, HandleSIGTERM);
    registerSignalHandler(SIGINT, HandleSIGTERM);

    // Reopen debug.log on SIGHUP
    registerSignalHandler(SIGHUP, HandleSIGHUP);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#else
    SetConsoleCtrlHandler(consoleCtrlHandler, true);
#endif

    std::set_new_handler(new_handler_terminate);

    return true;
}

bool AppInitParameterInteraction(const ArgsManager& args)
{
    const CChainParams& chainparams = Params();
    // ********************************************************* Step 2: parameter interactions

    // also see: InitParameterInteraction()

    // We drop UPnP support but kept the arg as hidden for now to display a friendlier error to user who have the
    // option in their config. TODO: remove (here and above) for version 30.0.
    if (!UpnpSetting::Value(args).isNull()) {
        InitWarning(_("Option '-upnp' is set but UPnP support was dropped in version 29.0. Consider using '-natpmp' instead."));
    }

    // Error if network-specific options (-addnode, -connect, etc) are
    // specified in default section of config file, but not overridden
    // on the command line or in this chain's section of the config file.
    ChainType chain = args.GetChainType();
    if (chain == ChainType::SIGNET) {
        LogPrintf("Signet derived magic (message start): %s\n", HexStr(chainparams.MessageStart()));
    }
    bilingual_str errors;
    for (const auto& arg : args.GetUnsuitableSectionOnlyArgs()) {
        errors += strprintf(_("Config setting for %s only applied on %s network when in [%s] section.") + Untranslated("\n"), arg, ChainTypeToString(chain), ChainTypeToString(chain));
    }

    if (!errors.empty()) {
        return InitError(errors);
    }

    // Testnet3 deprecation warning
    if (chain == ChainType::TESTNET) {
        LogInfo("Warning: Support for testnet3 is deprecated and will be removed in an upcoming release. Consider switching to testnet4.\n");
    }

    // Warn if unrecognized section name are present in the config file.
    bilingual_str warnings;
    for (const auto& section : args.GetUnrecognizedSections()) {
        warnings += strprintf(Untranslated("%s:%i ") + _("Section [%s] is not recognized.") + Untranslated("\n"), section.m_file, section.m_line, section.m_name);
    }

    if (!warnings.empty()) {
        InitWarning(warnings);
    }

    if (!fs::is_directory(args.GetBlocksDirPath())) {
        return InitError(strprintf(_("Specified blocks directory \"%s\" does not exist."), BlocksdirSetting::Get(args)));
    }

    // parse and validate enabled filter types
    std::string blockfilterindex_value = BlockfilterindexSettingStr::Get(args);
    if (blockfilterindex_value == "" || blockfilterindex_value == "1") {
        g_enabled_filter_types = AllBlockFilterTypes();
    } else if (blockfilterindex_value != "0") {
        const std::vector<std::string> names = BlockfilterindexSetting::Get(args);
        for (const auto& name : names) {
            BlockFilterType filter_type;
            if (!BlockFilterTypeByName(name, filter_type)) {
                return InitError(strprintf(_("Unknown -blockfilterindex value %s."), name));
            }
            g_enabled_filter_types.insert(filter_type);
        }
    }

    // Signal NODE_P2P_V2 if BIP324 v2 transport is enabled.
    if (V2transportSetting::Get(args)) {
        g_local_services = ServiceFlags(g_local_services | NODE_P2P_V2);
    }

    // Signal NODE_COMPACT_FILTERS if peerblockfilters and basic filters index are both enabled.
    if (PeerblockfiltersSetting::Get(args)) {
        if (g_enabled_filter_types.count(BlockFilterType::BASIC) != 1) {
            return InitError(_("Cannot set -peerblockfilters without -blockfilterindex."));
        }

        g_local_services = ServiceFlags(g_local_services | NODE_COMPACT_FILTERS);
    }

    if (PruneSetting::Get(args, 0)) {
        if (TxindexSetting::Get(args))
            return InitError(_("Prune mode is incompatible with -txindex."));
        if (ReindexChainstateSetting::Get(args)) {
            return InitError(_("Prune mode is incompatible with -reindex-chainstate. Use full -reindex instead."));
        }
    }

    // If -forcednsseed is set to true, ensure -dnsseed has not been set to false
    if (ForcednsseedSetting::Get(args) && !DnsseedSetting::Get(args, DEFAULT_DNSSEED)){
        return InitError(_("Cannot set -forcednsseed to true when setting -dnsseed to false."));
    }

    // -bind and -whitebind can't be set when not listening
    size_t nUserBind = BindSetting::Get(args).size() + WhitebindSetting::Get(args).size();
    if (nUserBind != 0 && !ListenSetting::Get(args, DEFAULT_LISTEN)) {
        return InitError(Untranslated("Cannot set -bind or -whitebind together with -listen=0"));
    }

    // if listen=0, then disallow listenonion=1
    if (!ListenSetting::Get(args, DEFAULT_LISTEN) && ListenonionSetting::Get(args, DEFAULT_LISTEN_ONION)) {
        return InitError(Untranslated("Cannot set -listen=0 together with -listenonion=1"));
    }

    // Make sure enough file descriptors are available. We need to reserve enough FDs to account for the bare minimum,
    // plus all manual connections and all bound interfaces. Any remainder will be available for connection sockets

    // Number of bound interfaces (we have at least one)
    int nBind = std::max(nUserBind, size_t(1));
    // Maximum number of connections with other nodes, this accounts for all types of outbounds and inbounds except for manual
    int user_max_connection = MaxconnectionsSetting::Get(args);
    if (user_max_connection < 0) {
        return InitError(Untranslated("-maxconnections must be greater or equal than zero"));
    }
    // Reserve enough FDs to account for the bare minimum, plus any manual connections, plus the bound interfaces
    int min_required_fds = MIN_CORE_FDS + MAX_ADDNODE_CONNECTIONS + nBind;

    // Try raising the FD limit to what we need (available_fds may be smaller than the requested amount if this fails)
    available_fds = RaiseFileDescriptorLimit(user_max_connection + min_required_fds);
    // If we are using select instead of poll, our actual limit may be even smaller
#ifndef USE_POLL
    available_fds = std::min(FD_SETSIZE, available_fds);
#endif
    if (available_fds < min_required_fds)
        return InitError(strprintf(_("Not enough file descriptors available. %d available, %d required."), available_fds, min_required_fds));

    // Trim requested connection counts, to fit into system limitations
    nMaxConnections = std::min(available_fds - min_required_fds, user_max_connection);

    if (nMaxConnections < user_max_connection)
        InitWarning(strprintf(_("Reducing -maxconnections from %d to %d, because of system limitations."), user_max_connection, nMaxConnections));

    // ********************************************************* Step 3: parameter-to-internal-flags
    if (auto result{init::SetLoggingCategories(args)}; !result) return InitError(util::ErrorString(result));
    if (auto result{init::SetLoggingLevel(args)}; !result) return InitError(util::ErrorString(result));

    nConnectTimeout = TimeoutSetting::Get(args);
    if (nConnectTimeout <= 0) {
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;
    }

    peer_connect_timeout = PeertimeoutSetting::Get(args);
    if (peer_connect_timeout <= 0) {
        return InitError(Untranslated("peertimeout must be a positive integer."));
    }

    // Sanity check argument for min fee for including tx in block
    // TODO: Harmonize which arguments need sanity checking and where that happens
    if (!BlockmintxfeeSetting::Value(args).isNull()) {
        if (!ParseMoney(BlockmintxfeeSetting::Get(args, ""))) {
            return InitError(AmountErrMsg("blockmintxfee", BlockmintxfeeSetting::Get(args, "")));
        }
    }

    nBytesPerSigOp = BytespersigopSetting::Get(args);

    if (!g_wallet_init_interface.ParameterInteraction()) return false;

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(MocktimeSetting::Get(args)); // SetMockTime(0) is a no-op

    if (PeerbloomfiltersSetting::Get(args))
        g_local_services = ServiceFlags(g_local_services | NODE_BLOOM);

    if (!TestSetting::Value(args).isNull()) {
        if (chainparams.GetChainType() != ChainType::REGTEST) {
            return InitError(Untranslated("-test=<option> can only be used with regtest"));
        }
        const std::vector<std::string> options = TestSetting::Get(args);
        for (const std::string& option : options) {
            auto it = std::find_if(TEST_OPTIONS_DOC.begin(), TEST_OPTIONS_DOC.end(), [&option](const std::string& doc_option) {
                size_t pos = doc_option.find(" (");
                return (pos != std::string::npos) && (doc_option.substr(0, pos) == option);
            });
            if (it == TEST_OPTIONS_DOC.end()) {
                InitWarning(strprintf(_("Unrecognised option \"%s\" provided in -test=<option>."), option));
            }
        }
    }

    // Also report errors from parsing before daemonization
    {
        kernel::Notifications notifications{};
        ChainstateManager::Options chainman_opts_dummy{
            .chainparams = chainparams,
            .datadir = args.GetDataDirNet(),
            .notifications = notifications,
        };
        auto chainman_result{ApplyArgsManOptions(args, chainman_opts_dummy)};
        if (!chainman_result) {
            return InitError(util::ErrorString(chainman_result));
        }
        BlockManager::Options blockman_opts_dummy{
            .chainparams = chainman_opts_dummy.chainparams,
            .blocks_dir = args.GetBlocksDirPath(),
            .notifications = chainman_opts_dummy.notifications,
        };
        auto blockman_result{ApplyArgsManOptions(args, blockman_opts_dummy)};
        if (!blockman_result) {
            return InitError(util::ErrorString(blockman_result));
        }
        CTxMemPool::Options mempool_opts{};
        auto mempool_result{ApplyArgsManOptions(args, chainparams, mempool_opts)};
        if (!mempool_result) {
            return InitError(util::ErrorString(mempool_result));
        }
    }

    return true;
}

static bool LockDataDirectory(bool probeOnly)
{
    // Make sure only a single Bitcoin process is using the data directory.
    const fs::path& datadir = gArgs.GetDataDirNet();
    switch (util::LockDirectory(datadir, ".lock", probeOnly)) {
    case util::LockResult::ErrorWrite:
        return InitError(strprintf(_("Cannot write to data directory '%s'; check permissions."), fs::PathToString(datadir)));
    case util::LockResult::ErrorLock:
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. %s is probably already running."), fs::PathToString(datadir), CLIENT_NAME));
    case util::LockResult::Success: return true;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

bool AppInitSanityChecks(const kernel::Context& kernel)
{
    // ********************************************************* Step 4: sanity checks
    auto result{kernel::SanityChecks(kernel)};
    if (!result) {
        InitError(util::ErrorString(result));
        return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), CLIENT_NAME));
    }

    if (!ECC_InitSanityCheck()) {
        return InitError(strprintf(_("Elliptic curve cryptography sanity check failure. %s is shutting down."), CLIENT_NAME));
    }

    // Probe the data directory lock to give an early error message, if possible
    // We cannot hold the data directory lock here, as the forking for daemon() hasn't yet happened,
    // and a fork will cause weird behavior to it.
    return LockDataDirectory(true);
}

bool AppInitLockDataDirectory()
{
    // After daemonization get the data directory lock again and hold on to it until exit
    // This creates a slight window for a race condition to happen, however this condition is harmless: it
    // will at most make us exit without printing a message to console.
    if (!LockDataDirectory(false)) {
        // Detailed error printed inside LockDataDirectory
        return false;
    }
    return true;
}

bool AppInitInterfaces(NodeContext& node)
{
    node.chain = node.init->makeChain();
    node.mining = node.init->makeMining();
    return true;
}

bool CheckHostPortOptions(const ArgsManager& args) {
    for (const std::string port_option : {
        "-port",
        "-rpcport",
    }) {
        if (args.IsArgSet(port_option)) {
            const std::string port = args.GetArg(port_option, "");
            uint16_t n;
            if (!ParseUInt16(port, &n) || n == 0) {
                return InitError(InvalidPortErrMsg(port_option, port));
            }
        }
    }

    for ([[maybe_unused]] const auto& [arg, unix] : std::vector<std::pair<std::string, bool>>{
        // arg name            UNIX socket support
        {"-i2psam",                 false},
        {"-onion",                  true},
        {"-proxy",                  true},
        {"-rpcbind",                false},
        {"-torcontrol",             false},
        {"-whitebind",              false},
        {"-zmqpubhashblock",        true},
        {"-zmqpubhashtx",           true},
        {"-zmqpubrawblock",         true},
        {"-zmqpubrawtx",            true},
        {"-zmqpubsequence",         true},
    }) {
        for (const std::string& socket_addr : args.GetArgs(arg)) {
            std::string host_out;
            uint16_t port_out{0};
            if (!SplitHostPort(socket_addr, port_out, host_out)) {
#ifdef HAVE_SOCKADDR_UN
                // Allow unix domain sockets for some options e.g. unix:/some/file/path
                if (!unix || !socket_addr.starts_with(ADDR_PREFIX_UNIX)) {
                    return InitError(InvalidPortErrMsg(arg, socket_addr));
                }
#else
                return InitError(InvalidPortErrMsg(arg, socket_addr));
#endif
            }
        }
    }

    return true;
}

// A GUI user may opt to retry once with do_reindex set if there is a failure during chainstate initialization.
// The function therefore has to support re-entry.
static ChainstateLoadResult InitAndLoadChainstate(
    NodeContext& node,
    bool do_reindex,
    const bool do_reindex_chainstate,
    CacheSizes& cache_sizes,
    const ArgsManager& args)
{
    const CChainParams& chainparams = Params();
    CTxMemPool::Options mempool_opts{
        .check_ratio = chainparams.DefaultConsistencyChecks() ? 1 : 0,
        .signals = node.validation_signals.get(),
    };
    Assert(ApplyArgsManOptions(args, chainparams, mempool_opts)); // no error can happen, already checked in AppInitParameterInteraction
    bilingual_str mempool_error;
    node.mempool = std::make_unique<CTxMemPool>(mempool_opts, mempool_error);
    if (!mempool_error.empty()) {
        return {ChainstateLoadStatus::FAILURE_FATAL, mempool_error};
    }
    LogPrintf("* Using %.1f MiB for in-memory UTXO set (plus up to %.1f MiB of unused mempool space)\n", cache_sizes.coins * (1.0 / 1024 / 1024), mempool_opts.max_size_bytes * (1.0 / 1024 / 1024));
    ChainstateManager::Options chainman_opts{
        .chainparams = chainparams,
        .datadir = args.GetDataDirNet(),
        .notifications = *node.notifications,
        .signals = node.validation_signals.get(),
    };
    Assert(ApplyArgsManOptions(args, chainman_opts)); // no error can happen, already checked in AppInitParameterInteraction
    BlockManager::Options blockman_opts{
        .chainparams = chainman_opts.chainparams,
        .blocks_dir = args.GetBlocksDirPath(),
        .notifications = chainman_opts.notifications,
    };
    Assert(ApplyArgsManOptions(args, blockman_opts)); // no error can happen, already checked in AppInitParameterInteraction
    try {
        node.chainman = std::make_unique<ChainstateManager>(*Assert(node.shutdown_signal), chainman_opts, blockman_opts);
    } catch (std::exception& e) {
        return {ChainstateLoadStatus::FAILURE_FATAL, strprintf(Untranslated("Failed to initialize ChainstateManager: %s"), e.what())};
    }
    ChainstateManager& chainman = *node.chainman;
    // This is defined and set here instead of inline in validation.h to avoid a hard
    // dependency between validation and index/base, since the latter is not in
    // libbitcoinkernel.
    chainman.snapshot_download_completed = [&node]() {
        if (!node.chainman->m_blockman.IsPruneMode()) {
            LogPrintf("[snapshot] re-enabling NODE_NETWORK services\n");
            node.connman->AddLocalServices(NODE_NETWORK);
        }
        LogPrintf("[snapshot] restarting indexes\n");
        // Drain the validation interface queue to ensure that the old indexes
        // don't have any pending work.
        Assert(node.validation_signals)->SyncWithValidationInterfaceQueue();
        for (auto* index : node.indexes) {
            index->Interrupt();
            index->Stop();
            if (!(index->Init() && index->StartBackgroundSync())) {
                LogPrintf("[snapshot] WARNING failed to restart index %s on snapshot chain\n", index->GetName());
            }
        }
    };
    node::ChainstateLoadOptions options;
    options.mempool = Assert(node.mempool.get());
    options.wipe_block_tree_db = do_reindex;
    options.wipe_chainstate_db = do_reindex || do_reindex_chainstate;
    options.prune = chainman.m_blockman.IsPruneMode();
    options.check_blocks = CheckblocksSetting::Get(args);
    options.check_level = ChecklevelSetting::Get(args);
    options.require_full_verification = !CheckblocksSetting::Value(args).isNull() || !ChecklevelSetting::Value(args).isNull();
    options.coins_error_cb = [] {
        uiInterface.ThreadSafeMessageBox(
            _("Error reading from database, shutting down."),
            "", CClientUIInterface::MSG_ERROR);
    };
    uiInterface.InitMessage(_("Loading block index…").translated);
    const auto load_block_index_start_time{SteadyClock::now()};
    auto catch_exceptions = [](auto&& f) {
        try {
            return f();
        } catch (const std::exception& e) {
            LogError("%s\n", e.what());
            return std::make_tuple(node::ChainstateLoadStatus::FAILURE, _("Error loading databases"));
        }
    };
    auto [status, error] = catch_exceptions([&] { return LoadChainstate(chainman, cache_sizes, options); });
    if (status == node::ChainstateLoadStatus::SUCCESS) {
        uiInterface.InitMessage(_("Verifying blocks…").translated);
        if (chainman.m_blockman.m_have_pruned && options.check_blocks > MIN_BLOCKS_TO_KEEP) {
            LogWarning("pruned datadir may not have more than %d blocks; only checking available blocks\n",
                       MIN_BLOCKS_TO_KEEP);
        }
        std::tie(status, error) = catch_exceptions([&] { return VerifyLoadedChainstate(chainman, options); });
        if (status == node::ChainstateLoadStatus::SUCCESS) {
            LogPrintf(" block index %15dms\n", Ticks<std::chrono::milliseconds>(SteadyClock::now() - load_block_index_start_time));
        }
    }
    return {status, error};
};

bool AppInitMain(NodeContext& node, interfaces::BlockAndHeaderTipInfo* tip_info)
{
    const ArgsManager& args = *Assert(node.args);
    const CChainParams& chainparams = Params();

    auto opt_max_upload = ParseByteUnits(MaxuploadtargetSetting::Get(args, DEFAULT_MAX_UPLOAD_TARGET), ByteUnit::M);
    if (!opt_max_upload) {
        return InitError(strprintf(_("Unable to parse -maxuploadtarget: '%s'"), MaxuploadtargetSetting::Get(args, "")));
    }

    // ********************************************************* Step 4a: application initialization
    if (!CreatePidFile(args)) {
        // Detailed error printed inside CreatePidFile().
        return false;
    }
    if (!init::StartLogging(args)) {
        // Detailed error printed inside StartLogging().
        return false;
    }

    LogPrintf("Using at most %i automatic connections (%i file descriptors available)\n", nMaxConnections, available_fds);

    // Warn about relative -datadir path.
    if (!DatadirSetting::Value(args).isNull() && !DatadirSettingPath::Get(args).is_absolute()) {
        LogPrintf("Warning: relative datadir option '%s' specified, which will be interpreted relative to the "
                  "current working directory '%s'. This is fragile, because if bitcoin is started in the future "
                  "from a different location, it will be unable to locate the current data files. There could "
                  "also be data loss if bitcoin is started while in a temporary directory.\n",
                  DatadirSetting::Get(args), fs::PathToString(fs::current_path()));
    }

    assert(!node.scheduler);
    node.scheduler = std::make_unique<CScheduler>();
    auto& scheduler = *node.scheduler;

    // Start the lightweight task scheduler thread
    scheduler.m_service_thread = std::thread(util::TraceThread, "scheduler", [&] { scheduler.serviceQueue(); });

    // Gather some entropy once per minute.
    scheduler.scheduleEvery([]{
        RandAddPeriodic();
    }, std::chrono::minutes{1});

    // Check disk space every 5 minutes to avoid db corruption.
    scheduler.scheduleEvery([&args, &node]{
        constexpr uint64_t min_disk_space = 50 << 20; // 50 MB
        if (!CheckDiskSpace(args.GetBlocksDirPath(), min_disk_space)) {
            LogError("Shutting down due to lack of disk space!\n");
            if (!(Assert(node.shutdown_request))()) {
                LogError("Failed to send shutdown signal after disk space check\n");
            }
        }
    }, std::chrono::minutes{5});

    assert(!node.validation_signals);
    node.validation_signals = std::make_unique<ValidationSignals>(std::make_unique<SerialTaskRunner>(scheduler));
    auto& validation_signals = *node.validation_signals;

    // Create client interfaces for wallets that are supposed to be loaded
    // according to -wallet and -disablewallet options. This only constructs
    // the interfaces, it doesn't load wallet data. Wallets actually get loaded
    // when load() and start() interface methods are called below.
    g_wallet_init_interface.Construct(node);
    uiInterface.InitWallet();

    if (interfaces::Ipc* ipc = node.init->ipc()) {
        for (std::string address : IpcbindSetting::Get(gArgs)) {
            try {
                ipc->listenAddress(address);
            } catch (const std::exception& e) {
                return InitError(strprintf(Untranslated("Unable to bind to IPC address '%s'. %s"), address, e.what()));
            }
            LogPrintf("Listening for IPC requests on address %s\n", address);
        }
    }

    /* Register RPC commands regardless of -server setting so they will be
     * available in the GUI RPC console even if external calls are disabled.
     */
    RegisterAllCoreRPCCommands(tableRPC);
    for (const auto& client : node.chain_clients) {
        client->registerRpcs();
    }
#ifdef ENABLE_ZMQ
    RegisterZMQRPCCommands(tableRPC);
#endif

    // Check port numbers
    if (!CheckHostPortOptions(args)) return false;

    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (ServerSetting::Get(args)) {
        uiInterface.InitMessage_connect(SetRPCWarmupStatus);
        if (!AppInitServers(node))
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }

    // ********************************************************* Step 5: verify wallet database integrity
    for (const auto& client : node.chain_clients) {
        if (!client->verify()) {
            return false;
        }
    }

    // ********************************************************* Step 6: network initialization
    // Note that we absolutely cannot open any actual connections
    // until the very end ("start node") as the UTXO/block state
    // is not yet setup and may end up being set up twice if we
    // need to reindex later.

    fListen = ListenSetting::Get(args, DEFAULT_LISTEN);
    fDiscover = DiscoverSetting::Get(args);

    PeerManager::Options peerman_opts{};
    ApplyArgsManOptions(args, peerman_opts);

    {

        // Read asmap file if configured
        std::vector<bool> asmap;
        if (!AsmapSetting::Value(args).isNull()) {
            fs::path asmap_path = AsmapSetting::Get(args);
            if (!asmap_path.is_absolute()) {
                asmap_path = args.GetDataDirNet() / asmap_path;
            }
            if (!fs::exists(asmap_path)) {
                InitError(strprintf(_("Could not find asmap file %s"), fs::quoted(fs::PathToString(asmap_path))));
                return false;
            }
            asmap = DecodeAsmap(asmap_path);
            if (asmap.size() == 0) {
                InitError(strprintf(_("Could not parse asmap file %s"), fs::quoted(fs::PathToString(asmap_path))));
                return false;
            }
            const uint256 asmap_version = (HashWriter{} << asmap).GetHash();
            LogPrintf("Using asmap version %s for IP bucketing\n", asmap_version.ToString());
        } else {
            LogPrintf("Using /16 prefix for IP bucketing\n");
        }

        // Initialize netgroup manager
        assert(!node.netgroupman);
        node.netgroupman = std::make_unique<NetGroupManager>(std::move(asmap));

        // Initialize addrman
        assert(!node.addrman);
        uiInterface.InitMessage(_("Loading P2P addresses…").translated);
        auto addrman{LoadAddrman(*node.netgroupman, args)};
        if (!addrman) return InitError(util::ErrorString(addrman));
        node.addrman = std::move(*addrman);
    }

    FastRandomContext rng;
    assert(!node.banman);
    node.banman = std::make_unique<BanMan>(args.GetDataDirNet() / "banlist", &uiInterface, BantimeSetting::Get(args));
    assert(!node.connman);
    node.connman = std::make_unique<CConnman>(rng.rand64(),
                                              rng.rand64(),
                                              *node.addrman, *node.netgroupman, chainparams, NetworkactiveSetting::Get(args));

    assert(!node.fee_estimator);
    // Don't initialize fee estimation with old data if we don't relay transactions,
    // as they would never get updated.
    if (!peerman_opts.ignore_incoming_txs) {
        bool read_stale_estimates = AcceptstalefeeestimatesSetting::Get(args);
        if (read_stale_estimates && (chainparams.GetChainType() != ChainType::REGTEST)) {
            return InitError(strprintf(_("acceptstalefeeestimates is not supported on %s chain."), chainparams.GetChainTypeString()));
        }
        node.fee_estimator = std::make_unique<CBlockPolicyEstimator>(FeeestPath(args), read_stale_estimates);

        // Flush estimates to disk periodically
        CBlockPolicyEstimator* fee_estimator = node.fee_estimator.get();
        scheduler.scheduleEvery([fee_estimator] { fee_estimator->FlushFeeEstimates(); }, FEE_FLUSH_INTERVAL);
        validation_signals.RegisterValidationInterface(fee_estimator);
    }

    for (const std::string& socket_addr : BindSetting::Get(args)) {
        std::string host_out;
        uint16_t port_out{0};
        std::string bind_socket_addr = socket_addr.substr(0, socket_addr.rfind('='));
        if (!SplitHostPort(bind_socket_addr, port_out, host_out)) {
            return InitError(InvalidPortErrMsg("-bind", socket_addr));
        }
    }

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<std::string> uacomments;
    for (const std::string& cmt : UacommentSetting::Get(args)) {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf(_("User Agent comment (%s) contains unsafe characters."), cmt));
        uacomments.push_back(cmt);
    }
    strSubVersion = FormatSubVersion(UA_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf(_("Total length of network version string (%i) exceeds maximum length (%i). Reduce the number or size of uacomments."),
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (!OnlynetSetting::Value(args).isNull()) {
        g_reachable_nets.RemoveAll();
        for (const std::string& snet : OnlynetSetting::Get(args)) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            g_reachable_nets.Add(net);
        }
    }

    if (CjdnsreachableSetting::Value(args).isNull()) {
        if (!OnlynetSetting::Value(args).isNull() && g_reachable_nets.Contains(NET_CJDNS)) {
            return InitError(
                _("Outbound connections restricted to CJDNS (-onlynet=cjdns) but "
                  "-cjdnsreachable is not provided"));
        }
        g_reachable_nets.Remove(NET_CJDNS);
    }
    // Now g_reachable_nets.Contains(NET_CJDNS) is true if:
    // 1. -cjdnsreachable is given and
    // 2.1. -onlynet is not given or
    // 2.2. -onlynet=cjdns is given

    // Requesting DNS seeds entails connecting to IPv4/IPv6, which -onlynet options may prohibit:
    // If -dnsseed=1 is explicitly specified, abort. If it's left unspecified by the user, we skip
    // the DNS seeds by adjusting -dnsseed in InitParameterInteraction.
    if (DnsseedSetting::Get(args) == true && !g_reachable_nets.Contains(NET_IPV4) && !g_reachable_nets.Contains(NET_IPV6)) {
        return InitError(strprintf(_("Incompatible options: -dnsseed=1 was explicitly specified, but -onlynet forbids connections to IPv4/IPv6")));
    };

    // Check for host lookup allowed before parsing any network related parameters
    fNameLookup = DnsSetting::Get(args);

    Proxy onion_proxy;

    bool proxyRandomize = ProxyrandomizeSetting::Get(args);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = ProxySetting::Get(args);
    if (proxyArg != "" && proxyArg != "0") {
        Proxy addrProxy;
        if (IsUnixSocketPath(proxyArg)) {
            addrProxy = Proxy(proxyArg, proxyRandomize);
        } else {
            const std::optional<CService> proxyAddr{Lookup(proxyArg, 9050, fNameLookup)};
            if (!proxyAddr.has_value()) {
                return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));
            }

            addrProxy = Proxy(proxyAddr.value(), proxyRandomize);
        }

        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address or hostname: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_CJDNS, addrProxy);
        SetNameProxy(addrProxy);
        onion_proxy = addrProxy;
    }

    const bool onlynet_used_with_onion{!OnlynetSetting::Value(args).isNull() && g_reachable_nets.Contains(NET_ONION)};

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = OnionSetting::Get(args);
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0
            onion_proxy = Proxy{};
            if (onlynet_used_with_onion) {
                return InitError(
                    _("Outbound connections restricted to Tor (-onlynet=onion) but the proxy for "
                      "reaching the Tor network is explicitly forbidden: -onion=0"));
            }
        } else {
            if (IsUnixSocketPath(onionArg)) {
                onion_proxy = Proxy(onionArg, proxyRandomize);
            } else {
                const std::optional<CService> addr{Lookup(onionArg, 9050, fNameLookup)};
                if (!addr.has_value() || !addr->IsValid()) {
                    return InitError(strprintf(_("Invalid -onion address or hostname: '%s'"), onionArg));
                }

                onion_proxy = Proxy(addr.value(), proxyRandomize);
            }
        }
    }

    if (onion_proxy.IsValid()) {
        SetProxy(NET_ONION, onion_proxy);
    } else {
        // If -listenonion is set, then we will (try to) connect to the Tor control port
        // later from the torcontrol thread and may retrieve the onion proxy from there.
        const bool listenonion_disabled{!ListenonionSetting::Get(args, DEFAULT_LISTEN_ONION)};
        if (onlynet_used_with_onion && listenonion_disabled) {
            return InitError(
                _("Outbound connections restricted to Tor (-onlynet=onion) but the proxy for "
                  "reaching the Tor network is not provided: none of -proxy, -onion or "
                  "-listenonion is given"));
        }
        g_reachable_nets.Remove(NET_ONION);
    }

    for (const std::string& strAddr : ExternalipSetting::Get(args)) {
        const std::optional<CService> addrLocal{Lookup(strAddr, GetListenPort(), fNameLookup)};
        if (addrLocal.has_value() && addrLocal->IsValid())
            AddLocal(addrLocal.value(), LOCAL_MANUAL);
        else
            return InitError(ResolveErrMsg("externalip", strAddr));
    }

#ifdef ENABLE_ZMQ
    g_zmq_notification_interface = CZMQNotificationInterface::Create(
        [&chainman = node.chainman](std::vector<uint8_t>& block, const CBlockIndex& index) {
            assert(chainman);
            return chainman->m_blockman.ReadRawBlockFromDisk(block, WITH_LOCK(cs_main, return index.GetBlockPos()));
        });

    if (g_zmq_notification_interface) {
        validation_signals.RegisterValidationInterface(g_zmq_notification_interface.get());
    }
#endif

    // ********************************************************* Step 7: load block chain

    node.notifications = std::make_unique<KernelNotifications>(Assert(node.shutdown_request), node.exit_status, *Assert(node.warnings));
    auto& kernel_notifications{*node.notifications};
    ReadNotificationArgs(args, kernel_notifications);

    // cache size calculations
    CacheSizes cache_sizes = CalculateCacheSizes(args, g_enabled_filter_types.size());

    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1f MiB for block index database\n", cache_sizes.block_tree_db * (1.0 / 1024 / 1024));
    if (TxindexSetting::Get(args)) {
        LogPrintf("* Using %.1f MiB for transaction index database\n", cache_sizes.tx_index * (1.0 / 1024 / 1024));
    }
    for (BlockFilterType filter_type : g_enabled_filter_types) {
        LogPrintf("* Using %.1f MiB for %s block filter index database\n",
                  cache_sizes.filter_index * (1.0 / 1024 / 1024), BlockFilterTypeName(filter_type));
    }
    LogPrintf("* Using %.1f MiB for chain state database\n", cache_sizes.coins_db * (1.0 / 1024 / 1024));

    assert(!node.mempool);
    assert(!node.chainman);

    bool do_reindex{ReindexSetting::Get(args)};
    const bool do_reindex_chainstate{ReindexChainstateSetting::Get(args)};

    // Chainstate initialization and loading may be retried once with reindexing by GUI users
    auto [status, error] = InitAndLoadChainstate(
        node,
        do_reindex,
        do_reindex_chainstate,
        cache_sizes,
        args);
    if (status == ChainstateLoadStatus::FAILURE && !do_reindex && !ShutdownRequested(node)) {
        // suggest a reindex
        bool do_retry = uiInterface.ThreadSafeQuestion(
            error + Untranslated(".\n\n") + _("Do you want to rebuild the databases now?"),
            error.original + ".\nPlease restart with -reindex or -reindex-chainstate to recover.",
            "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
        if (!do_retry) {
            return false;
        }
        do_reindex = true;
        if (!Assert(node.shutdown_signal)->reset()) {
            LogError("Internal error: failed to reset shutdown signal.\n");
        }
        std::tie(status, error) = InitAndLoadChainstate(
            node,
            do_reindex,
            do_reindex_chainstate,
            cache_sizes,
            args);
    }
    if (status != ChainstateLoadStatus::SUCCESS && status != ChainstateLoadStatus::INTERRUPTED) {
        return InitError(error);
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    if (ShutdownRequested(node)) {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }

    ChainstateManager& chainman = *Assert(node.chainman);

    assert(!node.peerman);
    node.peerman = PeerManager::make(*node.connman, *node.addrman,
                                     node.banman.get(), chainman,
                                     *node.mempool, *node.warnings,
                                     peerman_opts);
    validation_signals.RegisterValidationInterface(node.peerman.get());

    // ********************************************************* Step 8: start indexers

    if (TxindexSetting::Get(args)) {
        g_txindex = std::make_unique<TxIndex>(interfaces::MakeChain(node), cache_sizes.tx_index, false, do_reindex);
        node.indexes.emplace_back(g_txindex.get());
    }

    for (const auto& filter_type : g_enabled_filter_types) {
        InitBlockFilterIndex([&]{ return interfaces::MakeChain(node); }, filter_type, cache_sizes.filter_index, false, do_reindex);
        node.indexes.emplace_back(GetBlockFilterIndex(filter_type));
    }

    if (CoinstatsindexSetting::Get(args)) {
        g_coin_stats_index = std::make_unique<CoinStatsIndex>(interfaces::MakeChain(node), /*cache_size=*/0, false, do_reindex);
        node.indexes.emplace_back(g_coin_stats_index.get());
    }

    // Init indexes
    for (auto index : node.indexes) if (!index->Init()) return false;

    // ********************************************************* Step 9: load wallet
    for (const auto& client : node.chain_clients) {
        if (!client->load()) {
            return false;
        }
    }

    // ********************************************************* Step 10: data directory maintenance

    // if pruning, perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (chainman.m_blockman.IsPruneMode()) {
        if (chainman.m_blockman.m_blockfiles_indexed) {
            LOCK(cs_main);
            for (Chainstate* chainstate : chainman.GetAll()) {
                uiInterface.InitMessage(_("Pruning blockstore…").translated);
                chainstate->PruneAndFlush();
            }
        }
    } else {
        // Prior to setting NODE_NETWORK, check if we can provide historical blocks.
        if (!WITH_LOCK(chainman.GetMutex(), return chainman.BackgroundSyncInProgress())) {
            LogPrintf("Setting NODE_NETWORK on non-prune mode\n");
            g_local_services = ServiceFlags(g_local_services | NODE_NETWORK);
        } else {
            LogPrintf("Running node in NODE_NETWORK_LIMITED mode until snapshot background sync completes\n");
        }
    }

    // ********************************************************* Step 11: import blocks

    if (!CheckDiskSpace(args.GetDataDirNet())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(args.GetDataDirNet()))));
        return false;
    }
    if (!CheckDiskSpace(args.GetBlocksDirPath())) {
        InitError(strprintf(_("Error: Disk space is low for %s"), fs::quoted(fs::PathToString(args.GetBlocksDirPath()))));
        return false;
    }

    int chain_active_height = WITH_LOCK(cs_main, return chainman.ActiveChain().Height());

    // On first startup, warn on low block storage space
    if (!do_reindex && !do_reindex_chainstate && chain_active_height <= 1) {
        uint64_t assumed_chain_bytes{chainparams.AssumedBlockchainSize() * 1024 * 1024 * 1024};
        uint64_t additional_bytes_needed{
            chainman.m_blockman.IsPruneMode() ?
                std::min(chainman.m_blockman.GetPruneTarget(), assumed_chain_bytes) :
                assumed_chain_bytes};

        if (!CheckDiskSpace(args.GetBlocksDirPath(), additional_bytes_needed)) {
            InitWarning(strprintf(_(
                    "Disk space for %s may not accommodate the block files. " \
                    "Approximately %u GB of data will be stored in this directory."
                ),
                fs::quoted(fs::PathToString(args.GetBlocksDirPath())),
                chainparams.AssumedBlockchainSize()
            ));
        }
    }

#if HAVE_SYSTEM
    const std::string block_notify = BlocknotifySetting::Get(args);
    if (!block_notify.empty()) {
        uiInterface.NotifyBlockTip_connect([block_notify](SynchronizationState sync_state, const CBlockIndex* pBlockIndex) {
            if (sync_state != SynchronizationState::POST_INIT || !pBlockIndex) return;
            std::string command = block_notify;
            ReplaceAll(command, "%s", pBlockIndex->GetBlockHash().GetHex());
            std::thread t(runCommand, command);
            t.detach(); // thread runs free
        });
    }
#endif

    std::vector<fs::path> vImportFiles;
    for (const std::string& strFile : LoadblockSetting::Get(args)) {
        vImportFiles.push_back(fs::PathFromString(strFile));
    }

    node.background_init_thread = std::thread(&util::TraceThread, "initload", [=, &chainman, &args, &node] {
        ScheduleBatchPriority();
        // Import blocks
        ImportBlocks(chainman, vImportFiles);
        if (StopafterblockimportSetting::Get(args)) {
            LogPrintf("Stopping after block import\n");
            if (!(Assert(node.shutdown_request))()) {
                LogError("Failed to send shutdown signal after finishing block import\n");
            }
            return;
        }

        // Start indexes initial sync
        if (!StartIndexBackgroundSync(node)) {
            bilingual_str err_str = _("Failed to start indexes, shutting down..");
            chainman.GetNotifications().fatalError(err_str);
            return;
        }
        // Load mempool from disk
        if (auto* pool{chainman.ActiveChainstate().GetMempool()}) {
            LoadMempool(*pool, ShouldPersistMempool(args) ? MempoolPath(args) : fs::path{}, chainman.ActiveChainstate(), {});
            pool->SetLoadTried(!chainman.m_interrupt);
        }
    });

    // Wait for genesis block to be processed
    if (WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip() == nullptr)) {
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return !kernel_notifications.m_tip_block.IsNull() || ShutdownRequested(node);
        });
    }

    if (ShutdownRequested(node)) {
        return false;
    }

    // ********************************************************* Step 12: start node

    int64_t best_block_time{};
    {
        LOCK(chainman.GetMutex());
        const auto& tip{*Assert(chainman.ActiveTip())};
        LogPrintf("block tree size = %u\n", chainman.BlockIndex().size());
        chain_active_height = tip.nHeight;
        best_block_time = tip.GetBlockTime();
        if (tip_info) {
            tip_info->block_height = chain_active_height;
            tip_info->block_time = best_block_time;
            tip_info->verification_progress = GuessVerificationProgress(chainman.GetParams().TxData(), &tip);
        }
        if (tip_info && chainman.m_best_header) {
            tip_info->header_height = chainman.m_best_header->nHeight;
            tip_info->header_time = chainman.m_best_header->GetBlockTime();
        }
    }
    LogPrintf("nBestHeight = %d\n", chain_active_height);
    if (node.peerman) node.peerman->SetBestBlock(chain_active_height, std::chrono::seconds{best_block_time});

    // Map ports with NAT-PMP
    StartMapPort(NatpmpSetting::Get(args));

    CConnman::Options connOptions;
    connOptions.m_local_services = g_local_services;
    connOptions.m_max_automatic_connections = nMaxConnections;
    connOptions.uiInterface = &uiInterface;
    connOptions.m_banman = node.banman.get();
    connOptions.m_msgproc = node.peerman.get();
    connOptions.nSendBufferMaxSize = 1000 * MaxsendbufferSetting::Get(args);
    connOptions.nReceiveFloodSize = 1000 * MaxreceivebufferSetting::Get(args);
    connOptions.m_added_nodes = AddnodeSetting::Get(args);
    connOptions.nMaxOutboundLimit = *opt_max_upload;
    connOptions.m_peer_connect_timeout = peer_connect_timeout;
    connOptions.whitelist_forcerelay = WhitelistforcerelaySetting::Get(args);
    connOptions.whitelist_relay = WhitelistrelaySetting::Get(args);

    // Port to bind to if `-bind=addr` is provided without a `:port` suffix.
    const uint16_t default_bind_port =
        static_cast<uint16_t>(PortSetting::Get(args, Params().GetDefaultPort()));

    const auto BadPortWarning = [](const char* prefix, uint16_t port) {
        return strprintf(_("%s request to listen on port %u. This port is considered \"bad\" and "
                           "thus it is unlikely that any peer will connect to it. See "
                           "doc/p2p-bad-ports.md for details and a full list."),
                         prefix,
                         port);
    };

    for (const std::string& bind_arg : BindSetting::Get(args)) {
        std::optional<CService> bind_addr;
        const size_t index = bind_arg.rfind('=');
        if (index == std::string::npos) {
            bind_addr = Lookup(bind_arg, default_bind_port, /*fAllowLookup=*/false);
            if (bind_addr.has_value()) {
                connOptions.vBinds.push_back(bind_addr.value());
                if (IsBadPort(bind_addr.value().GetPort())) {
                    InitWarning(BadPortWarning("-bind", bind_addr.value().GetPort()));
                }
                continue;
            }
        } else {
            const std::string network_type = bind_arg.substr(index + 1);
            if (network_type == "onion") {
                const std::string truncated_bind_arg = bind_arg.substr(0, index);
                bind_addr = Lookup(truncated_bind_arg, BaseParams().OnionServiceTargetPort(), false);
                if (bind_addr.has_value()) {
                    connOptions.onion_binds.push_back(bind_addr.value());
                    continue;
                }
            }
        }
        return InitError(ResolveErrMsg("bind", bind_arg));
    }

    for (const std::string& strBind : WhitebindSetting::Get(args)) {
        NetWhitebindPermissions whitebind;
        bilingual_str error;
        if (!NetWhitebindPermissions::TryParse(strBind, whitebind, error)) return InitError(error);
        connOptions.vWhiteBinds.push_back(whitebind);
    }

    // If the user did not specify -bind= or -whitebind= then we bind
    // on any address - 0.0.0.0 (IPv4) and :: (IPv6).
    connOptions.bind_on_any = BindSetting::Get(args).empty() && WhitebindSetting::Get(args).empty();

    // Emit a warning if a bad port is given to -port= but only if -bind and -whitebind are not
    // given, because if they are, then -port= is ignored.
    if (connOptions.bind_on_any && !PortSetting::Value(args).isNull()) {
        const uint16_t port_arg = PortSetting::Get(args, 0);
        if (IsBadPort(port_arg)) {
            InitWarning(BadPortWarning("-port", port_arg));
        }
    }

    CService onion_service_target;
    if (!connOptions.onion_binds.empty()) {
        onion_service_target = connOptions.onion_binds.front();
    } else if (!connOptions.vBinds.empty()) {
        onion_service_target = connOptions.vBinds.front();
    } else {
        onion_service_target = DefaultOnionServiceTarget();
        connOptions.onion_binds.push_back(onion_service_target);
    }

    if (ListenonionSetting::Get(args, DEFAULT_LISTEN_ONION)) {
        if (connOptions.onion_binds.size() > 1) {
            InitWarning(strprintf(_("More than one onion bind address is provided. Using %s "
                                    "for the automatically created Tor onion service."),
                                  onion_service_target.ToStringAddrPort()));
        }
        StartTorControl(onion_service_target);
    }

    if (connOptions.bind_on_any) {
        // Only add all IP addresses of the machine if we would be listening on
        // any address - 0.0.0.0 (IPv4) and :: (IPv6).
        Discover();
    }

    for (const auto& net : WhitelistSetting::Get(args)) {
        NetWhitelistPermissions subnet;
        ConnectionDirection connection_direction;
        bilingual_str error;
        if (!NetWhitelistPermissions::TryParse(net, subnet, connection_direction, error)) return InitError(error);
        if (connection_direction & ConnectionDirection::In) {
            connOptions.vWhitelistedRangeIncoming.push_back(subnet);
        }
        if (connection_direction & ConnectionDirection::Out) {
            connOptions.vWhitelistedRangeOutgoing.push_back(subnet);
        }
    }

    connOptions.vSeedNodes = SeednodeSetting::Get(args);

    // Initiate outbound connections unless connect=0
    connOptions.m_use_addrman_outgoing = ConnectSetting::Value(args).isNull();
    if (!connOptions.m_use_addrman_outgoing) {
        const auto connect = ConnectSetting::Get(args);
        if (connect.size() != 1 || connect[0] != "0") {
            connOptions.m_specified_outgoing = connect;
        }
        if (!connOptions.m_specified_outgoing.empty() && !connOptions.vSeedNodes.empty()) {
            LogPrintf("-seednode is ignored when -connect is used\n");
        }

        if (!DnsseedSetting::Value(args).isNull() && DnsseedSetting::Get(args, DEFAULT_DNSSEED) && !ProxySetting::Value(args).isNull()) {
            LogPrintf("-dnsseed is ignored when -connect is used and -proxy is specified\n");
        }
    }

    const std::string& i2psam_arg = I2psamSetting::Get(args);
    if (!i2psam_arg.empty()) {
        const std::optional<CService> addr{Lookup(i2psam_arg, 7656, fNameLookup)};
        if (!addr.has_value() || !addr->IsValid()) {
            return InitError(strprintf(_("Invalid -i2psam address or hostname: '%s'"), i2psam_arg));
        }
        SetProxy(NET_I2P, Proxy{addr.value()});
    } else {
        if (!OnlynetSetting::Value(args).isNull() && g_reachable_nets.Contains(NET_I2P)) {
            return InitError(
                _("Outbound connections restricted to i2p (-onlynet=i2p) but "
                  "-i2psam is not provided"));
        }
        g_reachable_nets.Remove(NET_I2P);
    }

    connOptions.m_i2p_accept_incoming = I2pacceptincomingSetting::Get(args);

    if (!node.connman->Start(scheduler, connOptions)) {
        return false;
    }

    // ********************************************************* Step 13: finished

    // At this point, the RPC is "started", but still in warmup, which means it
    // cannot yet be called. Before we make it callable, we need to make sure
    // that the RPC's view of the best block is valid and consistent with
    // ChainstateManager's active tip.
    SetRPCWarmupFinished();

    uiInterface.InitMessage(_("Done loading").translated);

    for (const auto& client : node.chain_clients) {
        client->start(scheduler);
    }

    BanMan* banman = node.banman.get();
    scheduler.scheduleEvery([banman]{
        banman->DumpBanlist();
    }, DUMP_BANS_INTERVAL);

    if (node.peerman) node.peerman->StartScheduledTasks(scheduler);

#if HAVE_SYSTEM
    StartupNotify(args);
#endif

    return true;
}

bool StartIndexBackgroundSync(NodeContext& node)
{
    // Find the oldest block among all indexes.
    // This block is used to verify that we have the required blocks' data stored on disk,
    // starting from that point up to the current tip.
    // indexes_start_block='nullptr' means "start from height 0".
    std::optional<const CBlockIndex*> indexes_start_block;
    std::string older_index_name;
    ChainstateManager& chainman = *Assert(node.chainman);
    const Chainstate& chainstate = WITH_LOCK(::cs_main, return chainman.GetChainstateForIndexing());
    const CChain& index_chain = chainstate.m_chain;

    for (auto index : node.indexes) {
        const IndexSummary& summary = index->GetSummary();
        if (summary.synced) continue;

        // Get the last common block between the index best block and the active chain
        LOCK(::cs_main);
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(summary.best_block_hash);
        if (!index_chain.Contains(pindex)) {
            pindex = index_chain.FindFork(pindex);
        }

        if (!indexes_start_block || !pindex || pindex->nHeight < indexes_start_block.value()->nHeight) {
            indexes_start_block = pindex;
            older_index_name = summary.name;
            if (!pindex) break; // Starting from genesis so no need to look for earlier block.
        }
    };

    // Verify all blocks needed to sync to current tip are present.
    if (indexes_start_block) {
        LOCK(::cs_main);
        const CBlockIndex* start_block = *indexes_start_block;
        if (!start_block) start_block = chainman.ActiveChain().Genesis();
        if (!chainman.m_blockman.CheckBlockDataAvailability(*index_chain.Tip(), *Assert(start_block))) {
            return InitError(strprintf(Untranslated("%s best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)"), older_index_name));
        }
    }

    // Start threads
    for (auto index : node.indexes) if (!index->StartBackgroundSync()) return false;
    return true;
}
