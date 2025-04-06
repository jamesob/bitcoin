#include <fasttimer.h>

std::shared_ptr<EventLogger> g_event_logger = nullptr;


bool truncateLargeFile(std::ofstream& ofs, const std::string& filename) {
    // Get file descriptor from the ofstream
    // Note: This is implementation-dependent and might need adjustment
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd == -1) {
        std::cerr << "Failed to get file descriptor" << std::endl;
        return false;
    }

    // Get current file size without closing the stream
    struct stat st;
    if (fstat(fd, &st) != 0) {
        std::cerr << "Failed to get file size" << std::endl;
        return false;
    }

    off_t fileSize = st.st_size;
    const off_t maxSize = 500 * 1024 * 1024; // 500MB in bytes
    const off_t chunkSize = 50 * 1024 * 1024; // 50MB in bytes

    if (fileSize <= maxSize) {
        return true; // No truncation needed
    }

    // Open a separate handle for reading
    std::ifstream ifs(filename, std::ios::binary);
    if (!ifs.is_open()) {
        std::cerr << "Failed to open file for reading" << std::endl;
        return false;
    }

    // Read first line
    std::string firstLine;
    std::getline(ifs, firstLine);

    // Find position after 50MB aligned to newline
    off_t startPos = chunkSize;
    ifs.seekg(startPos);
    std::string buffer;
    std::getline(ifs, buffer); // Read to next newline
    startPos = ifs.tellg();

    // Read remaining content
    std::vector<char> remainingData(fileSize - startPos);
    ifs.read(remainingData.data(), fileSize - startPos);
    std::streamsize bytesRead = ifs.gcount();
    ifs.close();

    // Truncate and rewrite using a separate file descriptor
    int write_fd = open(filename.c_str(), O_WRONLY | O_TRUNC);
    if (write_fd == -1) {
        std::cerr << "Failed to open file for truncation" << std::endl;
        return false;
    }

    // Write first line and remaining data
    std::string firstLineWithNL = firstLine + "\n";
    int wrote = write(write_fd, firstLineWithNL.c_str(), firstLineWithNL.size());
    wrote = write(write_fd, remainingData.data(), bytesRead);
    if (wrote == -1) {
        // uhoh
    }
    close(write_fd);

    // Update the ofstream's file pointer to the end
    ofs.seekp(0, std::ios::end);

    return true;
}
