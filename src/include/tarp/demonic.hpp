#pragma once

#include <string>

namespace tarp {
namespace process {

// Become a daemon.
//
// This involves a number of things:
// - the process becomes the leader of its own separate session and its own
// group. That is, it disassocates itself from the parent process and its
// process group.
// - the process detaches itself from the controlling terminal so that
// closing the terminal session does not terminate the process.
// - if close_streams=true, all streams are pointed to /dev/null.
// (Otherwise nothing is done and is assumed the user might've
// configured the streams in a specific way).
//
// Note daemonize() normally does the following to daemonize the
// current process:
//  - fork()
//  - become session leader
//  - fork()
//
// However, if the current process is already child that has been
// forked from some parent process separately by the caller,
// then the first fork is unnecessary. So preforked=true should
// be specified in order to skip the first fork().
//
// Return true on success and false on failure.
bool daemonize(bool preforked, bool close_streams);

// Try to open pidfile and write the pid of the current process to it.
// If the file already exists, this will fail (unless ignore_exists=true),
// indicating an instance of the program is already running (or crashed
// and left behind its old pid file).
std::pair<bool, std::string> create_pid_file(const std::string &pid_file_path,
                                             bool ignore_exists);

// Read the pid from the specified pidfile. If there is an error
// (file does not exist, is unreadable, content is not a pid)
// {-1, errmsg} is returned, else {pid, ""}.
std::pair<int, std::string> read_pid_file(const std::string &pid_file_path);



}  // namespace process
}  // namespace tarp
