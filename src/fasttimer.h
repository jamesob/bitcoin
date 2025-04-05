#ifndef EVENT_LOGGER_H
#define EVENT_LOGGER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class EventLogger {
public:
    // Structure to hold event data
    struct EventData {
        std::chrono::nanoseconds start_time;
        std::chrono::nanoseconds end_time;
        std::string label;
        std::string metadata;
    };

    // Constructor: initialize logger with output file and buffer capacity
    EventLogger(const std::string& output_file, size_t buffer_capacity = 10'000)
        : m_output_file(output_file)
        , m_buffer_capacity(buffer_capacity)
        , m_running(false)
        , m_active_buffer(0) {

        // Initialize both buffers with the specified capacity
        m_buffers[0].reserve(buffer_capacity);
        m_buffers[1].reserve(buffer_capacity);
    }

    // Destructor: ensure writer thread is stopped and flush remaining events
    ~EventLogger() {
        stop();
    }

    // Start the logger and the writer thread
    void start() {
        // Prevent multiple starts
        if (m_running.exchange(true)) {
            return;
        }

        // Open the output file
        m_output_stream.open(m_output_file);
        if (!m_output_stream.is_open()) {
            m_running = false;
            throw std::runtime_error("Failed to open output file: " + m_output_file);
        }

        // Write CSV header
        m_output_stream << "start_time_ns,duration,label,metadata\n";

        // Start the writer thread
        m_writer_thread = std::thread(&EventLogger::writer_loop, this);
    }

    // Stop the logger and join the writer thread
    void stop() {
        if (!m_running.exchange(false)) {
            return;
        }

        // Notify the writer thread to exit
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_condition.notify_one();
        }

        // Wait for the writer thread to finish
        if (m_writer_thread.joinable()) {
            m_writer_thread.join();
        }

        // Write any remaining events in the buffer
        flush_buffer(m_buffers[m_active_buffer]);

        // Close the output stream
        m_output_stream.close();
    }

    // Log an event with start and end times
    void log_event(
        const std::string& label,
        std::chrono::nanoseconds start_time,
        std::chrono::nanoseconds end_time,
        const std::string& metadata
    ) {
        if (!m_running) {
            return;
        }

        // Create event data
        EventData event{start_time, end_time, label, metadata};

        // Add event to the active buffer
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_buffers[m_active_buffer].push_back(std::move(event));

            // Notify the writer thread if the buffer is full
            if (m_buffers[m_active_buffer].size() >= m_buffer_capacity) {
                m_condition.notify_one();
            }
        }
    }

    // Utility class to automatically time and log an event
    class ScopedEvent {
    public:
        ScopedEvent(EventLogger& logger, const std::string& label)
            : m_logger(logger)
            , m_label(label)
            , m_start_time(std::chrono::steady_clock::now().time_since_epoch()) {
        }

        void add_metadata(const std::string meta) {
            if (m_metadata.size() > 0) {
                m_metadata += "|";
            }
            m_metadata += meta;
        }

        ~ScopedEvent() {
            if (m_canceled) {
                return;
            }
            auto end_time = std::chrono::steady_clock::now().time_since_epoch();
            m_logger.log_event(
                m_label,
                std::chrono::duration_cast<std::chrono::nanoseconds>(m_start_time),
                std::chrono::duration_cast<std::chrono::nanoseconds>(end_time),
                m_metadata
            );
        }

        bool m_canceled{false};

    private:
        EventLogger& m_logger;
        std::string m_label;
        std::string m_metadata;
        std::chrono::steady_clock::duration m_start_time;
    };

    // Create a scoped event for automatic timing
    [[nodiscard]] ScopedEvent time_event(const std::string& label) {
        return ScopedEvent(*this, label);
    }

private:
    // Writer thread function
    void writer_loop() {
        while (m_running) {
            std::unique_lock<std::mutex> lock(m_mutex);

            // Wait for buffer to fill or timeout
            m_condition.wait_for(
                lock,
                std::chrono::milliseconds(500),
                [this]() {
                    return !m_running ||
                           m_buffers[m_active_buffer].size() >= m_buffer_capacity;
                }
            );

            // Swap buffers if we have data to write
            if (!m_buffers[m_active_buffer].empty()) {
                // Toggle active buffer
                size_t buffer_to_write = m_active_buffer;
                m_active_buffer = 1 - m_active_buffer;

                // Unlock before writing to minimize lock time
                lock.unlock();

                // Write the buffer to file
                flush_buffer(m_buffers[buffer_to_write]);

                // Clear the buffer for reuse (outside the lock)
                m_buffers[buffer_to_write].clear();
            }
        }
    }

    // Write all events in a buffer to the output file
    void flush_buffer(const std::vector<EventData>& buffer) {
        for (const auto& event : buffer) {
            auto dur = event.end_time - event.start_time;
            m_output_stream << event.start_time.count() << ","
                           << dur.count() << ","
                           << event.label << ","
                           << event.metadata << "\n";
        }
        m_output_stream.flush();
    }

    void increment_event_counter() {
        ++m_event_counter;
    }

private:
    std::string m_output_file;               // Path to output CSV file
    std::ofstream m_output_stream;           // File output stream
    size_t m_buffer_capacity;                // Maximum events per buffer
    std::vector<EventData> m_buffers[2];     // Double buffer for events
    std::atomic<bool> m_running;             // Flag to control the writer thread
    std::atomic<size_t> m_active_buffer;     // Index of the active buffer (0 or 1)
    std::mutex m_mutex;                      // Mutex for buffer access
    std::condition_variable m_condition;     // Condition variable for notifications
    std::thread m_writer_thread;             // Thread for writing events to file
    std::atomic<size_t> m_event_counter{0};
};

// Declare global pointer (nullptr until initialized)
extern std::shared_ptr<EventLogger> g_event_logger;

// Initialize the global event logger
inline void InitEventLogger(const std::string& output_file, size_t buffer_capacity = 1000) {
    if (g_event_logger) {
        throw std::runtime_error("Event logger already initialized");
    }

    g_event_logger = std::make_shared<EventLogger>(output_file, buffer_capacity);
    g_event_logger->start();
}

// Clean up the global event logger
inline void ShutdownEventLogger() {
    if (g_event_logger) {
        g_event_logger->stop();
        g_event_logger.reset();
    }
}

// Get the global event logger (with null check)
inline EventLogger& GetEventLogger() {
    if (!g_event_logger) {
        throw std::runtime_error("Event logger not initialized");
    }
    return *g_event_logger;
}

// RAII helper to time events using the global logger
class ScopedGlobalEvent {
public:
    explicit ScopedGlobalEvent(const std::string& label)
        : m_event(GetEventLogger().time_event(label)) {
    }

private:
    EventLogger::ScopedEvent m_event;
};

#endif // EVENT_LOGGER_H
