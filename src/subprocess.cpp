// local project
#include "ioutils.hxx"
#include "string_utils.hxx"
#include "tarp/subprocess.hpp"


#include <cmath>
#include <csignal>

#include <iostream>

extern "C" {
#include <sys/wait.h>
#include <unistd.h>
}

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <fmt/format.h>

namespace tarp {
namespace process {

using namespace std::chrono_literals;
using namespace std::string_literals;
namespace ioutils = tarp::utils::ioutils;
namespace string_utils = tarp::utils::string_utils;

namespace {
// NOTE: v AND its contents must always outlast cmd, otherwise you will get
// crashes. therefore cmd is meant as a 'view' of a const v that never changes
// and outlives it.
inline std::vector<const char *>
string_vector_to_c_string_vector(const std::vector<std::string> &v) {
    std::vector<const char *> out;
    for (unsigned i = 0; i < v.size(); ++i) {
        out.push_back(v[i].c_str());
    }

    out.push_back(nullptr);

    return out;
}
}  // namespace

subprocess::subprocess(asio::io_context &ioctx,
                       const std::vector<std::string> &cmdspec,
                       const std::map<std::string, std::string> envspec,
                       bool clear_env_first,
                       std::optional<std::chrono::milliseconds> deadline,
                       stream_config_tuple streams)
    : m_instream(std::move(streams.m_stdin))
    , m_outstream(std::move(streams.m_stdout))
    , m_errstream(std::move(streams.m_stderr))
    , m_ioctx(ioctx)
    , m_cmdspec(cmdspec)
    , m_envspec(envspec)
    , m_must_clear_env(clear_env_first)
    , m_time_limit(deadline) {
}

subprocess::~subprocess() {
    std::cerr << "subprocess dtor\n";
    kill_and_reap_child();
    kill_and_reap_group();
}

void subprocess::set_exit_callback(
  std::function<void(int pid, bool killed, int exit_code)> f) {
    m_sig_exit = std::move(f);
}

std::pair<bool, std::string> subprocess::run() {
    bool ok = false;
    std::string err;

    if (running()) {
        return {false, "process already running"};
    }

    std::tie(ok, err) = configure_streams();
    if (!ok) {
        return {false, "Failed to configure streams: " + err};
    }

    std::tie(ok, err) = fork_and_exec();
    if (!ok) {
        return {false, "Failed fork-exec maneuver: " + err};
    }

    arm_reaper();

    if (m_time_limit.has_value()) {
        arm_killer();
    }

    return {true, ""};
}

std::pair<bool, std::string> subprocess::configure_streams() {
    bool ok = false;
    std::string e;

#define REQUIRE_OK(f)      \
    std::tie(ok, e) = f(); \
    if (!ok) {             \
        return {false, e}; \
    }

    REQUIRE_OK(configure_stdin);
    REQUIRE_OK(configure_stdout);
    REQUIRE_OK(configure_stderr);
#undef REQUIRE_OK

    return {true, ""};
}

std::pair<bool, std::string> subprocess::wait() {
    // ioctx must not be running if this is called, since it gets run here
    // instead, and that is how we block here.
    if (!m_ioctx.stopped()) {
        return {false, "io_context already running"};
    }

    bool finished = false;

    m_sig_exit_internal = [&](int, bool, int) {
        finished = true;
    };

    m_ioctx.restart();

    auto [ok, e] = run();
    if (!ok) {
        return {false, e};
    }

    m_ioctx.run();

    m_sig_exit = nullptr;

    if (!finished) {
        throw std::logic_error(
          "wait returned without the process having exited");
    }

    return {ok, ""};
}

std::pair<bool, std::string> subprocess::configure_stdin() {
    int fd = m_instream.get_fd();

    // nothing to do, leave as is.
    if (fd < 0) {
        return {true, ""};
    }

    auto [isopen, err] = ioutils::fd_open_for_reading(fd);
    if (!isopen) {
        return {false,
                "misconfigured stdin stream, fd " + std::to_string(fd) +
                  " not open for reading"};
    }

    return {true, ""};
}

std::pair<bool, std::string> subprocess::configure_stdout() {
    int fd = m_outstream.get_fd();

    // nothing to do, leave as is.
    if (fd < 0) {
        return {true, ""};
    }

    auto [isopen, err] = ioutils::fd_open_for_writing(fd);
    if (!isopen) {
        return {false, "misconfigured stdout stream, fd not open for writing"};
    }

    return {true, ""};
}

std::pair<bool, std::string> subprocess::configure_stderr() {
    int fd = m_errstream.get_fd();

    // nothing to do, leave as is.
    if (fd < 0) {
        return {true, ""};
    }

    auto [isopen, err] = ioutils::fd_open_for_writing(fd);
    if (!isopen) {
        return {false, "misconfigured stderr stream, fd not open for writing"};
    }

    return {true, ""};
}

std::pair<bool, std::string> subprocess::fork_and_exec() {
    pid_t child_pid = fork();

    if (child_pid < 0) {
        return {false, "failed fork(): "s + strerror(errno)};
    }

    if (child_pid > 0) {
        m_child_pid = child_pid;
        // std::cerr << "child pid set to " << m_child_pid << std::endl;
        return {true, ""};
    }

    // ===== in child =====
    auto maybe_duplicate =
      [](int description_to_use, auto stream_fd, auto errmsg) {
          // if < 0, the intention is to do nothing, leave stream as is.
          if (description_to_use < 0) {
              return;
          }
          auto [ok, e] = ioutils::duplicate_fd(description_to_use, stream_fd);
          if (!ok) {
              std::cerr << errmsg << ": " << e << std::endl;
          }
      };

    maybe_duplicate(m_instream.get_fd(), STDIN_FILENO, "failed to dup stdin");
    maybe_duplicate(
      m_outstream.get_fd(), STDOUT_FILENO, "failed to dup stdout");
    maybe_duplicate(
      m_errstream.get_fd(), STDERR_FILENO, "failed to dup stderr");

    populate_environment();

    auto cmd = string_vector_to_c_string_vector(m_cmdspec);

    // execvp(cmd[0], (char *const *)&cmd[0]);
    execvp(cmd[0], const_cast<char *const *>(&cmd[0]));

    std::cerr << std::format("Failed exec : '{}'", strerror(errno))
              << std::endl;
    exit(127);
}

void subprocess::arm_killer(std::chrono::milliseconds time_limit) {
    m_deadline.expires_after(time_limit);
    m_deadline.async_wait([this](auto error_code) {
        if (error_code) {
            return;
        }

        kill_and_reap_child();
        kill_and_reap_group();
        emit_exit_signal();
    });
}

void subprocess::emit_exit_signal() {
    bool was_killed = killed();
    auto exit_code = get_exit_code();

    // NOTE: normally we could use sigc::signal or our own implementation of
    // the observer pattern, but we we already depend on asio and I'd like to
    // minimize the number of dependencies. So we just invoke some old-school
    // callbacks.
    if (m_sig_exit) {
        std::invoke(m_sig_exit, m_child_pid, was_killed, exit_code);
    }

    if (m_sig_exit_internal) {
        std::invoke(m_sig_exit_internal, m_child_pid, was_killed, exit_code);
    }
}

void subprocess::kill_and_reap_child() {
    std::cerr << "kill_and_reap called. m_child_pid=" << m_child_pid
              << std::endl;
    m_reap_timer.cancel();

    // don't want to kill the entire process group etc !
    if (m_child_pid < 0) {
        return;
    }

    // std::cerr << "Killing child with pid=" << m_child_pid << std::endl;
    if (kill(m_child_pid, SIGTERM) < 0) {
        std::cerr << std::format("Failed to kill subprocess (pid={}): {}",
                                 m_child_pid,
                                 strerror(errno))
                  << std::endl;
        return;
    }

    int wstatus = -1;
    if (waitpid(m_child_pid, &wstatus, 0) != m_child_pid) {
        std::cerr << std::format("waitpid() error: '{}'", strerror(errno))
                  << std::endl;
    }

    m_child_pid = -1;
    decode_exit_status_code(wstatus);
    std::cerr << "killed_and_reaped. m_child_pid=" << m_child_pid << std::endl;
}

void subprocess::decode_exit_status_code(int exit_code) {
    /* 'normal' termination */
    if (WIFEXITED(exit_code)) {
        m_exit_code = WEXITSTATUS(exit_code);
        m_was_killed = false;
        return;
    } else if (WIFSIGNALED(exit_code)) {
        /* terminated by signal -- either by the killer subprocess
         * or something else */
        m_was_killed = true;
        m_exit_code = -1;
        return;
    }
}

std::string subprocess::get_exit_status_string() const {
    if (m_was_killed) {
        return "killed";
    }
    if (m_exit_code >= 0) {
        return "exit code "s + std::to_string(m_exit_code);
    }

    return "UNKNOWN";
}

int subprocess::get_exit_code() const {
    return m_exit_code;
}

void subprocess::arm_killer() {
    arm_killer(*m_time_limit);
}

std::pair<bool, std::string> subprocess::send_signal(int signal) {
    if (!running()) {
        return {false, "process not running"};
    }

    int ret = kill(m_child_pid, signal);

    if (ret < 0) {
        return {false, "failed to send signal to process: "s + strerror(errno)};
    }

    return {true, ""};
}

std::pair<bool, std::string> subprocess::interrupt() {
    return send_signal(SIGINT);
}

void subprocess::arm_reaper() {
    if (m_child_pid < 0) {
        return;
    }

    m_reap_timer.expires_after(m_REAP_POLL_INTERVAL);
    m_reap_timer.async_wait([this](auto error_code) {
        if (error_code) {
            return;
        }

        // std::cerr << "arm_reaper called, child_pid=" << m_child_pid << "\n";

        int wstatus = -1;
        int ret = waitpid(m_child_pid, &wstatus, WNOHANG);

        // child exists, but not reaped.
        if (ret == 0) {
            arm_reaper();
            return;
        }

        if (ret != m_child_pid) {
            std::cerr << std::format("waitpid() error: '{}'", strerror(errno))
                      << std::endl;
            arm_reaper();
            return;
        }

        m_deadline.cancel();
        decode_exit_status_code(wstatus);
        int pid = -1;
        std::swap(m_child_pid, pid);

        std::cerr << "Child (pid="s + std::to_string(pid) + ") reaped.\n";
        kill_and_reap_group();
        emit_exit_signal();
    });
}

void subprocess::async_terminate() {
    // not running.
    if (m_child_pid < 0) {
        return;
    }

    arm_killer(0ms);
}

void subprocess::terminate() {
    // not running.
    if (m_child_pid < 0) {
        return;
    }

    kill_and_reap_child();
    kill_and_reap_group();
    emit_exit_signal();
}

void subprocess::populate_environment() {
    if (m_must_clear_env) {
        if (clearenv()) {
            std::cerr << "clearenv() failure: "s + strerror(errno);
            exit(1);
        }
    }

    for (const auto &[k, v] : m_envspec) {
        if (setenv(k.c_str(), v.c_str(), 1) == -1) {
            std::cerr << "setenv() failure: "s + strerror(errno);
            exit(1);
        }
    }

    return;
}

void subprocess::kill_and_reap_group() {
    // the child we forked, as well as all its children, if any, (unless they
    // have changed their groups) will have the same process group id as the
    // current process. We want to kill and reap the entire group with the
    // exception of the current process. The way that we do it here is:
    // - we move the current process out of its own group into the group of its
    // parent
    // - the former group will now contain all the process we want and need to
    // terminate.
    // - we send SIGKILL to the group we vacated.

    // the group this process is currently in, which contains this process
    // and all its descendants (unless they have changed their group).

    pid_t old_group = ::getpgid(getpid());

    // group of the parent of this process
    pid_t new_group = ::getpgid(::getppid());

    // called in the past already.
    if (new_group == old_group) {
        return;
    }

    std::cerr << "new group: " << new_group << std::endl;

    if (::setpgid(::getpid(), new_group) < 0) {
        std::cerr << "Failed to change process group id from " << old_group
                  << " to " << new_group << ": " << strerror(errno)
                  << std::endl;
        return;
    }

    std::cerr << "changed pgid from " << old_group << " to "
              << ::getpgid(getpid()) << std::endl;

    std::cerr << "Process with pid " << getpid() << " ppid " << getppid()
              << " pgid " << getpgid(getpid()) << " killing group with pgid "
              << old_group << std::endl;

    if (killpg(old_group, SIGKILL) < 0) {
        std::cerr << "Failed to send SIGKILL to process group with pgid="
                  << old_group << ": " << strerror(errno) << std::endl;
        return;
    }

    // reap all the processes killed; NOTE: we don't care here about the exit
    // status of the processes we reap. The direct child (m_child_pid) would've
    // been killed and reaped separately of what we do here. So at this point
    // we don't need the information, we are just cleaning up after ourselves
    // to prevent zombies.
    int ret = 0;
    // continue until either no children are left or we run into an error.
    while (true) {
        ret = waitpid(-1, nullptr, WNOHANG);

        if (ret > 0) {
            std::cerr
              << std::format(
                   "Child (pid {}, pgid {}) reaped by process with pid {}",
                   ret,
                   old_group,
                   getpid())
              << std::endl;
        }
        // children exist but have not changed state. We just killed everything
        // so this should never happen.
        else if (ret == 0) {
            std::cerr << "Children exist in group with pgid " << old_group
                      << " but have not changed state (unexpected) ..."
                      << std::endl;
            break;
        } else if (ret == -1) {
            if (errno != ECHILD) {
                std::cerr << "waitpid() error in process with pid="
                          << ::getpid() << ": " << strerror(errno) << std::endl;
            }
            break;
        }
    }
}

}  // namespace process
}  // namespace tarp
