// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/fs.h>
#include <util/syserror.h>

#ifndef WIN32
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/utsname.h>
#include <unistd.h>
#else
#include <codecvt>
#include <limits>
#include <windows.h>
#endif

#include <cassert>
#include <cerrno>
#include <string>

namespace fs {

std::function<bool(const path&)> g_mock_create_dirs{nullptr};

std::function<bool(const path&)> g_mock_exists{nullptr};

std::function<bool(const path&)> g_mock_remove{nullptr};

bool remove(const path& p)
{
    if (g_mock_remove) {
        return g_mock_remove(p);
    }
    return std::filesystem::remove(p);
}

std::function<bool(const path&, std::error_code&)> g_mock_remove_ec{nullptr};

bool remove(const path& p, std::error_code& ec)
{
    if (g_mock_remove) {
        return g_mock_remove_ec(p, ec);
    }
    return std::filesystem::remove(p, ec);
}

std::function<void(const path&, const path&)> g_mock_rename{nullptr};

void rename(const path& old_p, const path& new_p)
{
    if (g_mock_rename) {
        return g_mock_rename(old_p, new_p);
    }
    return std::filesystem::rename(old_p, new_p);
}

} // fs

namespace fsbridge {

std::function<FILE*(const fs::path&, const char*)> g_mock_fopen{nullptr};

FILE *fopen(const fs::path& p, const char *mode)
{
    if (g_mock_fopen) {
        return g_mock_fopen(p, mode);
    }
#ifndef WIN32
    return ::fopen(p.c_str(), mode);
#else
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t> utf8_cvt;
    return ::_wfopen(p.wstring().c_str(), utf8_cvt.from_bytes(mode).c_str());
#endif
}

fs::path AbsPathJoin(const fs::path& base, const fs::path& path)
{
    assert(base.is_absolute());
    return path.empty() ? base : fs::path(base / path);
}

#ifndef WIN32

static std::string GetErrorReason()
{
    return SysErrorString(errno);
}

FileLock::FileLock(const fs::path& file)
{
    fd = open(file.c_str(), O_RDWR);
    if (fd == -1) {
        reason = GetErrorReason();
    }
}

FileLock::~FileLock()
{
    if (fd != -1) {
        close(fd);
    }
}

bool FileLock::TryLock()
{
    if (fd == -1) {
        return false;
    }

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if (fcntl(fd, F_SETLK, &lock) == -1) {
        reason = GetErrorReason();
        return false;
    }

    return true;
}
#else

static std::string GetErrorReason() {
    return Win32ErrorString(GetLastError());
}

FileLock::FileLock(const fs::path& file)
{
    hFile = CreateFileW(file.wstring().c_str(),  GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        reason = GetErrorReason();
    }
}

FileLock::~FileLock()
{
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
}

bool FileLock::TryLock()
{
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    _OVERLAPPED overlapped = {};
    if (!LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, std::numeric_limits<DWORD>::max(), std::numeric_limits<DWORD>::max(), &overlapped)) {
        reason = GetErrorReason();
        return false;
    }
    return true;
}
#endif

std::string get_filesystem_error_message(const fs::filesystem_error& e)
{
#ifndef WIN32
    return e.what();
#else
    // Convert from Multi Byte to utf-16
    std::string mb_string(e.what());
    int size = MultiByteToWideChar(CP_ACP, 0, mb_string.data(), mb_string.size(), nullptr, 0);

    std::wstring utf16_string(size, L'\0');
    MultiByteToWideChar(CP_ACP, 0, mb_string.data(), mb_string.size(), &*utf16_string.begin(), size);
    // Convert from utf-16 to utf-8
    return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t>().to_bytes(utf16_string);
#endif
}

} // namespace fsbridge
