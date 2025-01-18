#pragma once

#include <string>

namespace tarp {
namespace utils {
namespace ioutils {

// NOTE: a socket (which is both readable and writable) will return true in both
// functions. Conversely, for a pipe only one function will return true
// depending on whether they are run on the read or the write end of the pipe.
std::pair<bool, std::string> fd_open_for_reading(int fd);
std::pair<bool, std::string> fd_open_for_writing(int fd);

std::pair<bool, std::string> attach_fd_to_dev_null(int fd);

// Close fd_to_redirect and reopen to point to the same file description as
// pointed to by the target_description fd.
std::pair<bool, std::string> duplicate_fd(int target_description,
                                          int fd_to_redirect);

// Check if fd is open.
bool is_valid_fd(int fd);

// Check if fd is open for readin or writing. Note a socket
// is readable AND writable so both of these will return true.
// Conversely, a pipe has readable and writable ends, so only
// one of these will return true depending on which end of the
// pipe they are called on.
std::pair<bool, std::string> fd_open_for_reading(int fd);
std::pair<bool, std::string> fd_open_for_writing(int fd);

// check if two files are identical (same size, same content).
// In case of error, the second result will be a non-empty string and the bool
// should be ignored. The bool (if there is no error) indicates whether the
// files are identical or not.
std::pair<bool, std::string> files_identical(const std::string &fpath_a,
                                             const std::string &fpath_b);

// Generate a file with num_bytes bytes, with each byte
// picked at random from the [0, 255] range.
bool generate_file_random_bytes(const std::string &abspath,
                                std::size_t num_bytes);

}  // namespace ioutils
}  // namespace utils
}  // namespace tarp
