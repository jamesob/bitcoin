// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ringbuffer.h>
#include <test/test_bitcoin.h>

#include <thread>
#include <vector>
#include <set>
#include <mutex>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(ringbuffer_tests, BasicTestingSetup)

/**
 * Exercise RingBuffer's interface with basic, serial usage.
 */
BOOST_AUTO_TEST_CASE(ringbuffer_serial_usage)
{
    RingBuffer<int, 10> rb;
    std::vector<int> processed_buffer;

    BOOST_REQUIRE_EQUAL(rb.Size(), 0);
    BOOST_REQUIRE_EQUAL(rb.MaxSize(), 10);
    BOOST_REQUIRE_EQUAL(rb.PushBack(10), 1);
    BOOST_REQUIRE_EQUAL(rb.PushBack(11), 2);
    BOOST_REQUIRE_EQUAL(rb.Size(), 2);
    BOOST_REQUIRE_EQUAL(rb.PopFront(), 10);
    BOOST_REQUIRE_EQUAL(rb.Size(), 1);
    BOOST_REQUIRE_EQUAL(rb.PopFront(), 11);
    BOOST_REQUIRE_EQUAL(rb.Size(), 0);

    // Test overflows -- 12 elements added with 2 elements overwritten.
    for (int i = 0; i < 12; ++i) rb.PushBack(i, /*no_overwrite*/ false);

    BOOST_REQUIRE_EQUAL(rb.Size(), 10);

    std::unique_ptr<int> popped;

    // Consume two elements; ensure the overwrite clobbered the earliest two
    // elements.
    popped = rb.PollForOne();
    BOOST_REQUIRE_EQUAL(rb.Size(), 9);
    BOOST_REQUIRE_EQUAL(*popped, 2);

    popped = rb.PollForOne();
    BOOST_REQUIRE_EQUAL(rb.Size(), 8);
    BOOST_REQUIRE_EQUAL(*popped, 3);

    // Ensure PopAll consumes the remaining elements.
    std::vector<int> all = rb.PopAll();

    BOOST_REQUIRE_EQUAL(rb.Size(), 0);
    BOOST_REQUIRE_EQUAL(all.size(), 8);

    auto it_all = all.begin();

    for (int i = 4; i < 12; ++i) {
        BOOST_REQUIRE_EQUAL(*it_all++, i);
    }
}

/**
 * Have many threads write to the buffer simultaneously and ensure that no data is lost.
 */
BOOST_AUTO_TEST_CASE(ringbuffer_threaded_usage)
{

    RingBuffer<int, 1000> rb;
    std::map<int, int> counts;
    std::vector<std::thread> producer_threads;
    int num_producer_threads = 10;
    int num_items_per_thread = 100;

    for (int i = 0; i < num_producer_threads; ++i) counts.emplace(i, 0);

    // Have each producer thread write its thread number `num_items_per_thread` times.
    auto Producer = [&rb, num_items_per_thread](int thread_num) {
        for (int i = 0; i < num_items_per_thread; ++i) {
            rb.PushBack(thread_num);
        }
    };

    // Consume writes and add the thread numbers to a counter.
    std::thread consumer_thread([&]() {
        std::unique_ptr<int> got;
        while (got = rb.PollForOne()) {
            ++counts[*got];
        }
    });

    for (int i = 0; i < num_producer_threads; ++i) {
        producer_threads.push_back(std::thread(Producer, i));
    }

    for (auto& thread : producer_threads) thread.join();

    // Give a little time for the consumption to complete -- 400ms should be
    // more than enough.
    MilliSleep(400);
    rb.SignalStopWaiting();
    consumer_thread.join();

    BOOST_REQUIRE_EQUAL(rb.Size(), 0);

    for (int i = 0; i < num_producer_threads; ++i) {
        BOOST_REQUIRE_EQUAL(counts[i], num_items_per_thread);
    }
}

/**
 * Test block-instead-of-overwrite behavior for PushBack() by writing more elements than
 * the buffer has capacity for in one thread and ensuring it blocks.
 */
BOOST_AUTO_TEST_CASE(ringbuffer_no_overwrite)
{

    RingBuffer<int, 10> rb;
    std::atomic<bool> rb_full;
    rb_full.store(false);

    // This thread will attempt to append more data than the buffer has room for,
    // and will only complete execution once a few reads happen to clear up space.
    std::thread producer_thread([&rb, &rb_full]() {
        for (int i = 1; i < 15; ++i) {
            rb.PushBack(i, /*no_overwrite*/ true);
            if (rb.Size() == rb.MaxSize()) rb_full.store(true);
        }
    });

    // Sleep until the buffer has filled up.
    while (!rb_full.load()) MilliSleep(10);
    BOOST_REQUIRE_EQUAL(rb.Size(), 10);

    // Ensure the earliest data written still exists in the buffer.
    BOOST_REQUIRE_EQUAL(rb.PopFront(), 1);
    BOOST_REQUIRE_EQUAL(rb.PopFront(), 2);
    BOOST_REQUIRE_EQUAL(*(rb.PollForOne()), 3);
    BOOST_REQUIRE_EQUAL(*(rb.PollForOne()), 4);

    // All queued writes should have happened.
    producer_thread.join();
    BOOST_REQUIRE_EQUAL(rb.Size(), 10);

    for (int i = 5; i < 15; ++i) {
        BOOST_REQUIRE_EQUAL(rb.PopFront(), i);
    }
}

// TODO: deduplicate this with scheduler_tests
static void MilliSleep(uint64_t n)
{
#if defined(HAVE_WORKING_BOOST_SLEEP_FOR)
    boost::this_thread::sleep_for(boost::chrono::milliseconds(n));
#elif defined(HAVE_WORKING_BOOST_SLEEP)
    boost::this_thread::sleep(boost::posix_time::milliseconds(n));
#else
    //should never get here
    #error missing boost sleep implementation
#endif
}

BOOST_AUTO_TEST_SUITE_END()
