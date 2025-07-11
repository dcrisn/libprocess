#pragma once

// c stdlib
#include <fcntl.h>
#include <unistd.h>

// c++ stdlib
#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>

// 3rd Party
#include <asio/io_context.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/steady_timer.hpp>

namespace tarp {
namespace process {

// NOTE: the asio version used in fact already has readable_pipe and
// writable_pipe, but we keep the old interface written here to minimize
// the dependency on asio so that this library can work with older asio
// versions.

// The readable end of a pipe.
// NOTE: the fd is closed in the dtor, so therefore no copy-ctor/copy assignment
// operator is provided.
// NOTE: the readable_pipe is constructed uninitialized. Association with an
// fd must be done through assign_fd().
class readable_pipe {
public:
    readable_pipe(const readable_pipe &) = delete;
    readable_pipe &operator=(const readable_pipe &) = delete;
    readable_pipe(readable_pipe &&) = default;
    readable_pipe &operator=(readable_pipe &&) = default;

    readable_pipe() = default;

    ~readable_pipe() { close(); }

    // Release ownership of the associated fd. The fd will therefore
    // no longer be closed in the dtor.
    int release() {
        int fd = m_fd;
        m_fd = -1;
        m_peer_fd = -1;
        return fd;
    }

    // Initialize the readable_pipe.
    void assign_fd(int read_end_fd, int write_end_fd) {
        m_fd = read_end_fd;
        m_peer_fd = write_end_fd;
    }

    void close() { ::close(release()); }

    int get_fd() const { return m_fd; }

    int get_peer_fd() const { return m_peer_fd; }

private:
    int m_fd = -1;
    int m_peer_fd = -1;
};

class writable_pipe {
public:
    writable_pipe(const writable_pipe &) = delete;
    writable_pipe &operator=(const writable_pipe &) = delete;
    writable_pipe(writable_pipe &&) = default;
    writable_pipe &operator=(writable_pipe &&) = default;

    writable_pipe() = default;

    ~writable_pipe() { close(); }

    void assign_fd(int read_end_fd, int write_end_fd) {
        m_fd = write_end_fd;
        m_peer_fd = read_end_fd;
    }

    int release() {
        int fd = m_fd;
        m_fd = -1;
        m_peer_fd = -1;
        return fd;
    }

    void close() { ::close(release()); }

    int get_fd() const { return m_fd; }

    int get_peer_fd() const { return m_peer_fd; }

private:
    int m_fd = -1;
    int m_peer_fd = -1;
};

// Create a pipe and connect the specified read and write ends.
inline void connect_pipe(readable_pipe &readable_end,
                         writable_pipe &writable_end) {
    using namespace std::string_literals;
    errno = 0;
    int fds[2] = {-1, -1};

    if (readable_end.get_fd() >= 0 or readable_end.get_peer_fd() >= 0 or
        writable_end.get_fd() >= 0 or writable_end.get_peer_fd() >= 0) {
        throw std::logic_error(
          "connect_pipe() called on already-initialized pipe ends");
    }

    if (pipe(fds) != 0) {
        throw std::runtime_error("pipe() error: "s + strerror(errno));
    }

    // std::cerr << "assigning fds: " << fds[0] << " , " << fds[1] << std::endl;
    readable_end.assign_fd(fds[0], fds[1]);
    writable_end.assign_fd(fds[0], fds[1]);
}

// Create a pipe and return the connected read and write ends.
inline std::pair<readable_pipe, writable_pipe> make_pipe() {
    readable_pipe r;
    writable_pipe w;
    connect_pipe(r, w);
    return {std::move(r), std::move(w)};
}

// Helper class representing the stream configuration for one of the standard
// streams (stdin, stdout, stderr) to be passed to the subprocess class.
// This tells the subprocess class what to do with a given stream.
// Not to be used directly; use instream_config and outstream_config instead.
class stream_config {
public:
    // not copiable, since that would break any fd-ownership semantics.
    stream_config(const stream_config &) = delete;
    stream_config &operator=(const stream_config &) = delete;

    stream_config &operator=(stream_config &&other) {
        m_fd = other.m_fd;
        other.m_fd = -1;
        m_must_close = other.m_must_close;
        other.m_must_close = false;
        return *this;
    }

    stream_config(stream_config &&other) { *this = std::move(other); }

    virtual ~stream_config() { close(); }

    int get_fd() const { return m_fd; }

protected:
    // default: do nothing, leave stream as is.
    stream_config() : m_fd(-1), m_must_close(false) {}

    // user-provided and user-MANAGED fd. Use it, but do not close it.
    stream_config(int fd) : m_fd(fd), m_must_close(false) {}

    // open the file path using the specified access mode (r/w/rw).
    stream_config(const std::string &fpath, const std::string &s) {
        using namespace std::string_literals;

        // rw-r-----
        mode_t mask = S_IRUSR | S_IWUSR | S_IRGRP;
        mode_t access = -1;
        if (s == "r") {
            access = O_RDONLY;
        } else if (s == "w") {
            access = O_WRONLY;
            access |= O_CREAT | O_TRUNC;
        } else if (s == "rw") {
            access = O_RDWR;
            access |= O_CREAT | O_TRUNC;
        } else {
            throw std::invalid_argument("string argument must be r|w|rw");
        }

        errno = 0;
        m_fd = open(fpath.c_str(), access, mask);
        if (m_fd < 0) {
            throw std::runtime_error("Failed to open file ('"s + fpath +
                                     "'): " + strerror(errno));
        }
        m_must_close = true;
    }

    // bind stream to /dev/null.
    stream_config(std::nullptr_t) : stream_config("/dev/null", "rw") {}

    // make a writable_pipe, connect it to r, and use it for the stream
    // (stout/stderr).
    stream_config(readable_pipe &r) {
        m_must_close = false;

        // if not already connected
        if (r.get_fd() < 0) {
            writable_pipe w;
            connect_pipe(r, w);
            m_fd = w.release();
            m_must_close = true;
            return;
        }

        m_fd = r.get_peer_fd();
    }

    // make a readable_pipe, connect it to w, and use it for the stream (stdin).
    stream_config(writable_pipe &w) {
        m_must_close = false;

        // if not already connected
        if (w.get_fd() < 0) {
            readable_pipe r;
            connect_pipe(r, w);
            m_fd = r.release();
            m_must_close = true;
            return;
        }

        m_fd = w.get_peer_fd();
    }

private:
    void close() {
        if (!m_must_close) {
            return;
        }
        ::close(m_fd);
        m_fd = -1;
    }

    int m_fd = -1;
    bool m_must_close = false;
};

// configuration for an input stream (stdin) that we sink data into.
class sink_config : public stream_config {
public:
    sink_config(sink_config &&) = default;
    sink_config &operator=(sink_config &&) = default;

    sink_config() : stream_config() {}

    sink_config(int fd) : stream_config(fd) {}

    sink_config(const std::string &fpath) : stream_config(fpath, "r") {}

    sink_config(std::nullptr_t) : stream_config(nullptr) {}

    sink_config(writable_pipe &w) : stream_config(w) {}
};

// configuration for an output strean (stdout,stderr) that we source data from.
class source_config : public stream_config {
public:
    source_config(source_config &&) = default;
    source_config &operator=(source_config &&) = default;

    source_config() : stream_config() {}

    source_config(int fd) : stream_config(fd) {}

    source_config(const std::string &fpath) : stream_config(fpath, "w") {}

    source_config(std::nullptr_t) : stream_config(nullptr) {}

    source_config(readable_pipe &w) : stream_config(w) {}
};

struct stream_config_tuple {
    stream_config_tuple(sink_config &&stdin_config,
                        source_config &&stdout_config,
                        source_config &&stderr_config)
        : m_stdin(std::move(stdin_config))
        , m_stdout(std::move(stdout_config))
        , m_stderr(std::move(stderr_config)) {}

    stream_config_tuple() = default;

    sink_config m_stdin {};
    source_config m_stdout {}, m_stderr {};
};

// Construct a subprocess specification that can then be run later via .run().
//
// --> cmdspec
// A command specification, one string per argument.
// e.g. "bash", "-c", "./myscript.sh".
// The first string represents the actual program to invoke. If the path does
// not contain a slash, the PATHs are searched as with execvp.
//
// --> envspec
// variables to be set into the environment of the child process.
// If clear_env_first=true, then the environment of the child is first emptied.
// Otherwise the environment is simply added to, and any existing variables are
// overridden.
//
// --> deadline
// If deadline is set, then the process will be killed automatically if it has
// not exited on its own by the deadline.
//
// --> streams
// This is a 3-tuple (<stdin, stdout, stderr>) that specifies the configuration
// of the standard streams. All of them accept the following for their
// construction:
// - nullptr: associated the stream with /dev/null.
//
// - {} (empty/default ctor): do nothing, leave the streams as they are.
//
// - int : some arbitrary, correctly pre-opened (i.e. open for reading
// for stdin, open for writing for stdout or stder), file descriptor to use
// for the stream.
//
// - string: a file path to a file to open. This will automatically be opened
// in the right mode depending on the stream (opened for reading for stdin,
// opened for writing for stdout or stderr).
//
// - a subprocess::writable_pipe for stdin.
// - a subprocess:readable_pipe for stdin or stderr.
// NOTE: when a {readable,writable}_pipe is provided, it may be uninitialized.
// If already initialized, the class will just retrieve the peer-end fd.
// Otherwise this class will automatically create the peer end (read or write
// end, as appropriate) and connect to it the aforementioned pipe passed in.
// Therefore the stdin stream_config expects to be given a writable_pipe, and
// it will create a readable_pipe and connect it to the writable_pipe. The
// child process will then use the readable_pipe end to read what is written
// via the writable_pipe end.
//
// NOTE: the subprocess created in the system is bound in lifetime to the class;
// if a process was spawned, it will be terminated when the subprocess class
// destructor is invoked. If this is not desirable, then the process should
// detach itself by daemonizing.
class subprocess {
public:
    using envmap_t = std::map<std::string, std::string>;
    using stream_config_tuple_t = stream_config_tuple;

    template<typename... vargs>
    static std::pair<std::unique_ptr<subprocess>, std::string>
    make(vargs &&...args) {
        std::unique_ptr<subprocess> proc;
        try {
            proc = std::make_unique<subprocess>(std::forward<vargs>(args)...);
            return {std::move(proc), ""};
        } catch (const std::exception &e) {
            using namespace std::string_literals;
            return {nullptr, "failed to construct subprocess: "s + e.what()};
        }
    }

    subprocess(asio::io_context &ioctx,
               const std::vector<std::string> &cmdspec,
               const envmap_t envspec = envmap_t {},
               bool clear_first = true,
               std::optional<std::chrono::milliseconds> deadline = std::nullopt,
               stream_config_tuple streams = stream_config_tuple {});

    ~subprocess();

    subprocess(const stream_config &) = delete;
    subprocess &operator=(const subprocess &) = delete;
    subprocess &operator=(subprocess &&other) = delete;
    subprocess(subprocess &&other) = delete;
    subprocess() = delete;

    // Create the child process and return immediately.
    // {false, error_msg} is returned in case of error.
    std::pair<bool, std::string> run();

    // Create the child process and block until it exits.
    std::pair<bool, std::string> wait();

    // Request the termination of the child process and return immediately.
    void async_terminate();

    // Request the termination of the child process and block until it exits.
    void terminate();

    // Send an arbitrary signal to the child process.
    std::pair<bool, std::string> send_signal(int signal);

    // Send a SIGINT to the child process.
    std::pair<bool, std::string> interrupt();

    auto pid() const { return m_child_pid; }

    // Get the exit code of the process. NOTE: this is only meaningful
    // if the process exited normally, so the caller should also check killed().
    int get_exit_code() const;

    // Get a prettier string indicating either the exit code or whether the
    // process was killed.
    std::string get_exit_status_string() const;

    // Check whether the process was killed (as opposed to exiting normally).
    bool killed() const { return m_was_killed; }

    // Check whether the process was either killed or exited normally with an
    // error code. NOTE: only makes sense to call this for a process that was
    // run().
    bool failed() const {
        return killed() or (!running() and get_exit_code() != 0);
    }

    // Check whether the process is running.
    bool running() const { return m_child_pid >= 0; }

    // Signal emitted when the process has exited (whether normally or
    // as the result of a kill).
    auto &signal_exit() { return m_sig_exit; }

    void set_exit_callback(
      std::function<void(int pid, bool killed, int exit_code)>);

private:
    std::pair<bool, std::string> configure_streams();
    std::pair<bool, std::string> configure_stdin();
    std::pair<bool, std::string> configure_stdout();
    std::pair<bool, std::string> configure_stderr();

    std::pair<bool, std::string> fork_and_exec();
    void populate_environment();
    void arm_killer();
    void arm_killer(std::chrono::milliseconds time_limit);
    void arm_reaper();
    void decode_exit_status_code(int exit_code);
    void kill_and_reap_child();
    void kill_and_reap_group();

    pid_t get_pid() const { return m_child_pid; }

    void emit_exit_signal();

private:
    static constexpr std::chrono::milliseconds m_REAP_POLL_INTERVAL {50};

    const sink_config m_instream;
    const source_config m_outstream;
    const source_config m_errstream;

    asio::io_context &m_ioctx;
    asio::steady_timer m_deadline {m_ioctx};
    asio::steady_timer m_reap_timer {m_ioctx};

    // pid of the child process we forked.
    int m_child_pid = -1;

    // The process group id of the child (and any children it spawns,
    // unless they change their groups). After forking, we move the
    // child process out of the current process group to its own
    // process group. We do this for job control so that we can
    // unambiguously kill and reap all the processes in that group
    // only, without interfering with other groups.
    int m_child_pgid = -1;

    const std::vector<std::string> m_cmdspec;
    const std::map<std::string, std::string> m_envspec;
    const bool m_must_clear_env = false;
    const std::optional<std::chrono::milliseconds> m_time_limit;

    using exit_callback_t =
      std::function<void(int pid, bool killed, int exit_code)>;

    exit_callback_t m_sig_exit;
    exit_callback_t m_sig_exit_internal;

    bool m_was_killed = false;
    int m_exit_code = -1;
};

}  // namespace process
}  // namespace tarp
