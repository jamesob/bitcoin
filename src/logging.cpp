// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <utiltime.h>
#include <mutex>
#include <condition_variable>
#include <thread>

const char * const DEFAULT_DEBUGLOGFILE = "debug.log";

/**
 * NOTE: the logger instances is leaked on exit. This is ugly, but will be
 * cleaned up by the OS/libc. Defining a logger as a global object doesn't work
 * since the order of destruction of static/global objects is undefined.
 * Consider if the logger gets destroyed, and then some later destructor calls
 * LogPrintf, maybe indirectly, and you get a core dump at shutdown trying to
 * access the logger. When the shutdown sequence is fully audited and tested,
 * explicit destruction of these objects can be implemented by changing this
 * from a raw pointer to a std::unique_ptr.
 *
 * This method of initialization was originally introduced in
 * ee3374234c60aba2cc4c5cd5cac1c0aefc2d817c.
 */
BCLog::Logger* const g_logger = new BCLog::Logger();

bool fLogIPs = DEFAULT_LOGIPS;

#define LOG_LINE_BUFFER_SIZE 128
static std::atomic_int g_next_pending_log_line(0);
static std::atomic_int g_next_undef_log_line(0);
static std::atomic_bool g_debug_log_flush_thread_exit;
static std::mutex g_log_buff_mutex;
static std::condition_variable g_log_buff_cv;
static std::array<std::string, LOG_LINE_BUFFER_SIZE> g_debug_log_buff;
static std::unique_ptr<std::thread> g_buff_flush_thread; // non-ptr fails to build in LTO?
static std::once_flag g_buff_flush_thread_started;

static void DebugLogFlush()
{
    while (true) {
        int next_pending_log = g_next_pending_log_line.load(std::memory_order_acquire);
        int next_undef_log = g_next_undef_log_line.load(std::memory_order_acquire);
        if (next_pending_log == next_undef_log) {
            if (g_debug_log_flush_thread_exit) return;
            std::unique_lock<std::mutex> lock(g_log_buff_mutex);
            while (next_pending_log == next_undef_log && !g_debug_log_flush_thread_exit) {
                g_log_buff_cv.wait(lock);
                next_pending_log = g_next_pending_log_line.load(std::memory_order_acquire);
                next_undef_log = g_next_undef_log_line.load(std::memory_order_acquire);
            }
        }

        while (next_pending_log != next_undef_log) {
            fwrite(g_debug_log_buff[next_pending_log].data(), 1, g_debug_log_buff[next_pending_log].size(), g_logger->m_fileout);
            g_debug_log_buff[next_pending_log].clear();
            g_debug_log_buff[next_pending_log].shrink_to_fit();
            next_pending_log = (next_pending_log + 1) % LOG_LINE_BUFFER_SIZE;
            g_next_pending_log_line.store(next_pending_log, std::memory_order_release);
            g_log_buff_cv.notify_one();
        }
    }
}

void StopDebugLogFlushThread() {
    g_debug_log_flush_thread_exit = true;
    {
        std::unique_lock<std::mutex> lock(g_log_buff_mutex);
        g_log_buff_cv.notify_all();
    }
    if (g_buff_flush_thread) {
        g_buff_flush_thread->join();
    }
}

static int FileWriteStr(const std::string &str, FILE *fp)
{
    std::call_once(g_buff_flush_thread_started, [] {
        g_buff_flush_thread.reset(new std::thread(DebugLogFlush));
        });

    std::unique_lock<std::mutex> lock(g_log_buff_mutex);
    int next_pending_log = g_next_pending_log_line.load(std::memory_order_acquire);
    int next_undef_log = g_next_undef_log_line.load(std::memory_order_acquire);
    while (next_pending_log == (next_undef_log + 1) % LOG_LINE_BUFFER_SIZE && !g_debug_log_flush_thread_exit) {
        g_log_buff_cv.wait(lock);
        next_pending_log = g_next_pending_log_line.load(std::memory_order_acquire);
        next_undef_log = g_next_undef_log_line.load(std::memory_order_acquire);
    }
    if (g_debug_log_flush_thread_exit) {
        return fwrite(str.data(), 1, str.size(), fp);
    } else {
        g_debug_log_buff[next_undef_log] = str;
        g_next_undef_log_line.store((next_undef_log + 1) % LOG_LINE_BUFFER_SIZE, std::memory_order_release);
        g_log_buff_cv.notify_all();
        return str.size();
    }
}

bool BCLog::Logger::OpenDebugLog()
{
    std::lock_guard<std::mutex> scoped_lock(m_file_mutex);

    assert(m_fileout == nullptr);
    assert(!m_file_path.empty());

    m_fileout = fsbridge::fopen(m_file_path, "a");
    if (!m_fileout) {
        return false;
    }

    setbuf(m_fileout, nullptr); // unbuffered
    // dump buffered messages from before we opened the log
    while (!m_msgs_before_open.empty()) {
        FileWriteStr(m_msgs_before_open.front(), m_fileout);
        m_msgs_before_open.pop_front();
    }

    return true;
}

void BCLog::Logger::EnableCategory(BCLog::LogFlags flag)
{
    m_categories |= flag;
}

bool BCLog::Logger::EnableCategory(const std::string& str)
{
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) return false;
    EnableCategory(flag);
    return true;
}

void BCLog::Logger::DisableCategory(BCLog::LogFlags flag)
{
    m_categories &= ~flag;
}

bool BCLog::Logger::DisableCategory(const std::string& str)
{
    BCLog::LogFlags flag;
    if (!GetLogCategory(flag, str)) return false;
    DisableCategory(flag);
    return true;
}

bool BCLog::Logger::WillLogCategory(BCLog::LogFlags category) const
{
    return (m_categories.load(std::memory_order_relaxed) & category) != 0;
}

bool BCLog::Logger::DefaultShrinkDebugFile() const
{
    return m_categories == BCLog::NONE;
}

struct CLogCategoryDesc
{
    BCLog::LogFlags flag;
    std::string category;
};

const CLogCategoryDesc LogCategories[] =
{
    {BCLog::NONE, "0"},
    {BCLog::NONE, "none"},
    {BCLog::NET, "net"},
    {BCLog::TOR, "tor"},
    {BCLog::MEMPOOL, "mempool"},
    {BCLog::HTTP, "http"},
    {BCLog::BENCH, "bench"},
    {BCLog::ZMQ, "zmq"},
    {BCLog::DB, "db"},
    {BCLog::RPC, "rpc"},
    {BCLog::ESTIMATEFEE, "estimatefee"},
    {BCLog::ADDRMAN, "addrman"},
    {BCLog::SELECTCOINS, "selectcoins"},
    {BCLog::REINDEX, "reindex"},
    {BCLog::CMPCTBLOCK, "cmpctblock"},
    {BCLog::RAND, "rand"},
    {BCLog::PRUNE, "prune"},
    {BCLog::PROXY, "proxy"},
    {BCLog::MEMPOOLREJ, "mempoolrej"},
    {BCLog::LIBEVENT, "libevent"},
    {BCLog::COINDB, "coindb"},
    {BCLog::QT, "qt"},
    {BCLog::LEVELDB, "leveldb"},
    {BCLog::ALL, "1"},
    {BCLog::ALL, "all"},
};

bool GetLogCategory(BCLog::LogFlags& flag, const std::string& str)
{
    if (str == "") {
        flag = BCLog::ALL;
        return true;
    }
    for (const CLogCategoryDesc& category_desc : LogCategories) {
        if (category_desc.category == str) {
            flag = category_desc.flag;
            return true;
        }
    }
    return false;
}

std::string ListLogCategories()
{
    std::string ret;
    int outcount = 0;
    for (const CLogCategoryDesc& category_desc : LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE && category_desc.flag != BCLog::ALL) {
            if (outcount != 0) ret += ", ";
            ret += category_desc.category;
            outcount++;
        }
    }
    return ret;
}

std::vector<CLogCategoryActive> ListActiveLogCategories()
{
    std::vector<CLogCategoryActive> ret;
    for (const CLogCategoryDesc& category_desc : LogCategories) {
        // Omit the special cases.
        if (category_desc.flag != BCLog::NONE && category_desc.flag != BCLog::ALL) {
            CLogCategoryActive catActive;
            catActive.category = category_desc.category;
            catActive.active = LogAcceptCategory(category_desc.flag);
            ret.push_back(catActive);
        }
    }
    return ret;
}

std::string BCLog::Logger::LogTimestampStr(const std::string &str)
{
    std::string strStamped;

    if (!m_log_timestamps)
        return str;

    if (m_started_new_line) {
        int64_t nTimeMicros = GetTimeMicros();
        strStamped = FormatISO8601DateTime(nTimeMicros/1000000);
        if (m_log_time_micros) {
            strStamped.pop_back();
            strStamped += strprintf(".%06dZ", nTimeMicros%1000000);
        }
        int64_t mocktime = GetMockTime();
        if (mocktime) {
            strStamped += " (mocktime: " + FormatISO8601DateTime(mocktime) + ")";
        }
        strStamped += ' ' + str;
    } else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        m_started_new_line = true;
    else
        m_started_new_line = false;

    return strStamped;
}


void BCLog::Logger::LogPrintStr(const std::string &str)
{
    std::string strTimestamped = LogTimestampStr(str);

    if (m_print_to_console) {
        // print to console
        fwrite(strTimestamped.data(), 1, strTimestamped.size(), stdout);
        fflush(stdout);
    }
    if (m_print_to_file) {
        std::lock_guard<std::mutex> scoped_lock(m_file_mutex);

        // buffer if we haven't opened the log yet
        if (m_fileout == nullptr) {
            m_msgs_before_open.push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (m_reopen_file) {
                m_reopen_file = false;
                m_fileout = fsbridge::freopen(m_file_path, "a", m_fileout);
                if (!m_fileout) {
                    return;
                }
                setbuf(m_fileout, nullptr); // unbuffered
            }

            FileWriteStr(strTimestamped, m_fileout);
        }
    }
}

void BCLog::Logger::ShrinkDebugFile()
{
    // Amount of debug.log to save at end when shrinking (must fit in memory)
    constexpr size_t RECENT_DEBUG_HISTORY_SIZE = 10 * 1000000;

    assert(!m_file_path.empty());

    // Scroll debug.log if it's getting too big
    FILE* file = fsbridge::fopen(m_file_path, "r");

    // Special files (e.g. device nodes) may not have a size.
    size_t log_size = 0;
    try {
        log_size = fs::file_size(m_file_path);
    } catch (boost::filesystem::filesystem_error &) {}

    // If debug.log file is more than 10% bigger the RECENT_DEBUG_HISTORY_SIZE
    // trim it down by saving only the last RECENT_DEBUG_HISTORY_SIZE bytes
    if (file && log_size > 11 * (RECENT_DEBUG_HISTORY_SIZE / 10))
    {
        // Restart the file with some of the end
        std::vector<char> vch(RECENT_DEBUG_HISTORY_SIZE, 0);
        if (fseek(file, -((long)vch.size()), SEEK_END)) {
            LogPrintf("Failed to shrink debug log file: fseek(...) failed\n");
            fclose(file);
            return;
        }
        int nBytes = fread(vch.data(), 1, vch.size(), file);
        fclose(file);

        file = fsbridge::fopen(m_file_path, "w");
        if (file)
        {
            fwrite(vch.data(), 1, nBytes, file);
            fclose(file);
        }
    }
    else if (file != nullptr)
        fclose(file);
}
