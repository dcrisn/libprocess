#include "ioutils.hxx"

#include <filesystem>
#include <fstream>
#include <random>

#include <cstring>

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

namespace tarp::utils::ioutils {

using namespace std::string_literals;
namespace fs = std::filesystem;

bool is_valid_fd(int fd) {
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

std::pair<bool, std::string> fd_open_for_reading(int fd) {
    errno = 0;

    int res = fcntl(fd, F_GETFL);
    if (res < 0) {
        return {false, strerror(errno)};
    }

    int file_access_mode = res & O_ACCMODE;

    // NOTE: the access mode flags are not actually flags so they cannot
    // be tested as 'file_access_mode & O_RDONLY'! for example,
    // O_RDONLY on this system is actually 0 so '&' would always evaluate
    // to 0 in that case.
    if (file_access_mode == O_RDONLY) {
        return {true, ""};
    }

    if (file_access_mode == O_RDWR) {
        return {true, ""};
    }

    return {false, ""};
}

std::pair<bool, std::string> fd_open_for_writing(int fd) {
    errno = 0;
    int res = fcntl(fd, F_GETFL);
    if (res < 0) {
        return {false, strerror(errno)};
    }

    auto file_access_mode = res & O_ACCMODE;

    if (file_access_mode == O_WRONLY) {
        return {true, ""};
    }

    if (file_access_mode == O_RDWR) {
        return {true, ""};
    }

    return {false, ""};
}

std::pair<bool, std::string> duplicate_fd(int target_description,
                                          int fd_to_redirect) {
    if (dup2(target_description, fd_to_redirect) < 0) {
        return {false, strerror(errno)};
    }
    return {true, ""};
}

// point fd to /dev/null
std::pair<bool, std::string> attach_fd_to_dev_null(int fd) {
    int nulldev_fd = open("/dev/null", O_RDWR);
    if (nulldev_fd == -1) {
        return {false, "Failed to open /dev/null: "s + strerror(errno)};
    }

    auto [ok, e] = duplicate_fd(nulldev_fd, fd);
    ::close(nulldev_fd);
    if (!ok) {
        return {false, "Failed /dev/null binding: "s + e};
    }

    return {true, ""};
}

std::pair<bool, std::string> files_identical(const std::string &fpath_a,
                                             const std::string &fpath_b) {
    std::ifstream a, b;
    a.open(fpath_a, std::ios_base::in | std::ios_base::binary);
    if (!a.is_open()) {
        return {false, "failed to open " + fpath_a};
    }

    b.open(fpath_a, std::ios_base::in | std::ios_base::binary);
    if (!b.is_open()) {
        return {false, "failed to open " + fpath_b};
    }

    if (fs::file_size(fpath_a) != fs::file_size(fpath_b)) {
        return {false, ""};
    }

    std::vector<char> buffer_a, buffer_b;
    constexpr std::size_t BUFFSZ = 1024 * 1024;
    buffer_a.resize(BUFFSZ);
    buffer_b.resize(BUFFSZ);

    std::size_t total_bytes_read_a = 0;
    std::size_t total_bytes_read_b = 0;

    while (!a.fail() and !b.fail()) {
        a.read(&buffer_a[0], buffer_a.size());
        auto bytes_read_a = a.gcount();
        total_bytes_read_a += bytes_read_a;

        b.read(&buffer_b[0], buffer_b.size());
        auto bytes_read_b = b.gcount();
        total_bytes_read_b += bytes_read_b;

        if (bytes_read_a != bytes_read_b or
            total_bytes_read_a != total_bytes_read_b) {
            throw std::logic_error("Unexpected condition");
        }

        for (unsigned i = 0; i < bytes_read_a; ++i) {
            if (buffer_a[i] != buffer_b[i]) {
                return {false, ""};
            }
        }
    }
    return {true, ""};
}

bool generate_file_random_bytes(const std::string &abspath,
                                std::size_t num_bytes) {
    std::ofstream of;
    of.open(abspath, std::ios_base::out | std::ios_base::binary);
    if (!of.is_open()) {
        return false;
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, 255);

    for (unsigned i = 0; i < num_bytes; ++i) {
        std::uint8_t value = dist(rng);
        of << value;
    }

    of.flush();
    of.close();
    return true;
}

};  // namespace tarp::utils::ioutils
