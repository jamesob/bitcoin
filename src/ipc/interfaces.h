#ifndef BITCOIN_IPC_INTERFACES_H
#define BITCOIN_IPC_INTERFACES_H

#include "policy/rbf.h" // For RBFTransactionState
#include "primitives/transaction.h"

#include <memory>
#include <vector>

class CBlock;
class CScheduler;
class CValidationState;
class uint256;
struct CBlockLocator;

namespace ipc {

//! Interface for giving wallet processes access to blockchain state.
class Chain
{
public:
    virtual ~Chain() {}

    //! Interface for querying locked chain state, used by legacy code that
    //! assumes state won't change between calls. New code should avoid using
    //! the LockedState interface and instead call higher-level Chain methods
    //! that return more information so the chain doesn't need to stay locked
    //! between calls.
    class LockedState
    {
    public:
        virtual ~LockedState() {}

        //! Get current chain height, not including genesis block (returns 0 if
        //! chain only contains genesis block, -1 if chain does not contain any
        //! blocks).
        virtual int getHeight() = 0;

        //! Get block height above genesis block. Returns 0 for genesis block, 1 for
        //! following block, and so on. Returns -1 for a block not included in the
        //! current chain.
        virtual int getBlockHeight(const uint256& hash) = 0;

        //! Get block depth. Returns 1 for chain tip, 2 for preceding block, and
        //! so on. Returns 0 for a block not included in the current chain.
        virtual int getBlockDepth(const uint256& hash) = 0;

        //! Get block hash.
        virtual uint256 getBlockHash(int height) = 0;

        //! Get block time.
        virtual int64_t getBlockTime(int height) = 0;

        //! Get max time of block and all ancestors.
        virtual int64_t getBlockTimeMax(int height) = 0;

        //! Get block median time past.
        virtual int64_t getBlockMedianTimePast(int height) = 0;

        //! Check if block is empty.
        virtual bool blockHasTransactions(int height) = 0;

        //! Read block from disk.
        virtual bool readBlockFromDisk(int height, CBlock& block) = 0;

        //! Estimate fraction of total transactions verified if blocks up to
        //! given height are verified.
        virtual double guessVerificationProgress(int height) = 0;

        //! Return height of earliest block in chain with timestamp equal or
        //! greater than the given time, or -1 if there is no block with a high
        //! enough timestamp.
        virtual int findEarliestAtLeast(int64_t time) = 0;

        //! Return height of last block in chain with timestamp less than the given,
        //! and height less than or equal to the given, or -1 if there is no such
        //! block.
        virtual int64_t findLastBefore(int64_t time, int start_height) = 0;

        //! Return height of the highest block on the chain that is an ancestor
        //! of the specified block. Also, optionally return the height of the
        //! specified block.
        virtual int findFork(const uint256& hash, int* height) = 0;

        //! Return true if block hash points to the current chain tip, or to a
        //! possible descendant of the current chain tip that isn't currently
        //! connected.
        virtual bool isPotentialTip(const uint256& hash) = 0;

        //! Get locator for the current chain tip.
        virtual CBlockLocator getLocator() = 0;

        //! Return height of block on the chain using locator.
        virtual int findLocatorFork(const CBlockLocator& locator) = 0;

        //! Check if transaction will be final given chain height current time.
        virtual bool checkFinalTx(const CTransaction& tx) = 0;

        //! Check whether segregated witness is enabled on the network.
        virtual bool isWitnessEnabled() = 0;

        //! Add transaction to memory pool.
        virtual bool acceptToMemoryPool(CTransactionRef tx, CValidationState& state) = 0;
    };

    //! Return LockedState interface. Chain is locked when this is called, and
    //! unlocked when the returned interface is freed.
    virtual std::unique_ptr<LockedState> lockState(bool try_lock = false) = 0;

    //! Return LockedState interface assuming chain is already locked. This
    //! method is temporary and is only used in a few places to avoid changing
    //! behavior while code is transitioned to use the LockState interface.
    virtual std::unique_ptr<LockedState> assumeLocked() = 0;

    //! Return whether node has the block and optionally return block metadata or contents.
    virtual bool findBlock(const uint256& hash, CBlock* block = nullptr, int64_t* time = nullptr) = 0;

    //! Get virtual transaction size.
    virtual int64_t getVirtualTransactionSize(const CTransaction& tx) = 0;

    //! Check if transaction is RBF opt in.
    virtual RBFTransactionState isRBFOptIn(const CTransaction& tx) = 0;

    //! Check if transaction has descendants in mempool.
    virtual bool hasDescendantsInMempool(const uint256& txid) = 0;

    //! Interface to let node manage chain clients (wallets, or maybe tools for
    //! monitoring and analysis in the future).
    class Client
    {
    public:
        virtual ~Client() {}

        //! Register rpcs.
        virtual void registerRpcs() = 0;

        //! Prepare for execution, loading any needed state.
        virtual bool prepare() = 0;

        //! Start client execution and provide a scheduler. (Scheduler is
        //! ignored if client is out-of-process).
        virtual void start(CScheduler& scheduler) = 0;

        //! Stop client execution and prepare for shutdown.
        virtual void stop() = 0;

        //! Shut down client.
        virtual void shutdown() = 0;
    };

    //! List of clients.
    using Clients = std::vector<std::unique_ptr<Client>>;
};

//! Protocol IPC interface should use to communicate with implementation.
enum Protocol {
    LOCAL, //!< Call functions linked into current executable.
};

//! Create IPC chain interface, communicating with requested protocol. Returns
//! null if protocol isn't implemented or is not available in the current build
//! configuration.
std::unique_ptr<Chain> MakeChain(Protocol protocol);

//! Chain client creation options.
struct ChainClientOptions
{
    //! Type of IPC chain client. Currently wallet processes are the only
    //! clients. In the future other types of client processes could be added
    //! (tools for monitoring, analysis, fee estimation, etc).
    enum Type { WALLET = 0 };
    Type type;

    //! For WALLET client, wallet filenames to load.
    std::vector<std::string> wallet_filenames;
};

//! Create chain client interface, communicating with requested protocol.
//! Returns null if protocol or client type aren't implemented or available in
//! the current build configuration.
std::unique_ptr<Chain::Client> MakeChainClient(Protocol protocol, Chain& chain, ChainClientOptions options);

//! Convenience function to return options object for wallet clients.
inline ChainClientOptions WalletOptions(std::vector<std::string> wallet_filenames = {})
{
    ChainClientOptions options;
    options.type = ChainClientOptions::WALLET;
    options.wallet_filenames = std::move(wallet_filenames);
    return options;
}

} // namespace ipc

#endif // BITCOIN_IPC_INTERFACES_H
