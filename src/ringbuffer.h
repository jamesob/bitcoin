// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RINGBUFFER_H
#define BITCOIN_RINGBUFFER_H

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

/**
 * A threadsafe circular buffer.
 *
 * Allows optional blocking behavior instead of overwriting when at capacity.
 */
template<typename ET, int S>
class RingBuffer
{
public:
    using value_type = ET;

    RingBuffer() : m_size(0), m_insert_at_idx(0), m_read_at_idx(0), m_stop_waiting(false) { }
    ~RingBuffer() { }

    /** @return the number of elements in the buffer. */
    inline size_t Size() const {
        std::lock_guard<std::mutex> lock(m_lock);
        return m_size;
    }
    constexpr size_t MaxSize() const { return S; }

    value_type PopFront()
    {
        std::lock_guard<std::mutex> lock(m_lock);
        return AssumeLockedPopFront();
    }

    /**
     * Push an element into the buffer.
     *
     * @arg no_overwrite  If true, block and wait to write instead of overwriting existing data.
     */
    size_t PushBack(const value_type& v, bool no_overwrite = true)
    {
        std::unique_lock<std::mutex> lock(m_lock);
        if (no_overwrite && m_size == S) {
            m_read_condvar.wait(lock, [this]() { return this->m_size < S; });
        }
        m_buffer[m_insert_at_idx] = v;

        // We're overwriting existing data, so increment the read index too.
        if (m_size > 0 && m_insert_at_idx == m_read_at_idx) m_read_at_idx = IncrementIdx(m_read_at_idx);
        if (m_size < S) ++m_size;
        m_insert_at_idx = IncrementIdx(m_insert_at_idx);

        return m_size;
    }

    /** Interrupt anyone waiting for reads. */
    void SignalStopWaiting() {
        m_stop_waiting.store(true);
    }

    /**
     * Block until the buffer has content to process, polling periodically, and
     * then return a pointer to an element. Allow interrupts by using SignalStopWaiting().
     *
     * @return false if the poll was interrupted without executing func.
     */
    std::unique_ptr<value_type> PollForOne(int poll_interval_ms = 200)
    {
        while (!m_stop_waiting.load()) {
            {
                std::unique_lock<std::mutex> lock(m_lock);
                if (m_size > 0) {
                    return std::unique_ptr<value_type>(new value_type(AssumeLockedPopFront()));
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms));
        }
        return nullptr;
    }

    /** @return all values currently in the buffer after popping them. */
    std::vector<value_type> PopAll()
    {
        std::unique_lock<std::mutex> lock(m_lock);
        std::vector<value_type> values;

        while (m_size > 0 && m_read_at_idx != m_insert_at_idx) {
            values.push_back(AssumeLockedPopFront());
        }
        return std::move(values);
    }

private:
    std::array<value_type, S> m_buffer;

    /** Number of elements in the buffer. */
    size_t m_size;

    /** Index at which the next insertion will happen. */
    size_t m_insert_at_idx;

    /** Index of the next element to read. */
    size_t m_read_at_idx;

    /** Set to signal that we should stop waiting for elements in, e.g., PollForOne(). */
    std::atomic<bool> m_stop_waiting;

    /** Notifies when a read has happened. */
    std::condition_variable m_read_condvar;

    /** Protects access to m_buffer, m_size, m_insert_at_idx, m_read_at_idx. */
    mutable std::mutex m_lock;

    /**
     * Pop an element off the front of the buffer and return it. Assumes caller
     * holds m_lock.
     */
    value_type AssumeLockedPopFront()
    {
        assert(m_size > 0);

        value_type data = std::move(m_buffer[m_read_at_idx]);
        m_read_at_idx = IncrementIdx(m_read_at_idx);
        --m_size;

        m_read_condvar.notify_one();
        return std::move(data);
    }

    inline size_t IncrementIdx(size_t val) const { return (val + 1) % S; }
};

#endif // BITCOIN_RINGBUFFER_H
