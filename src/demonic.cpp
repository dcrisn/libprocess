#include "common.hxx"
#include "string_utils.hxx"

#include <format>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
}

namespace tarp {
namespace process {

namespace string_utils = tarp::utils::string_utils;

//
bool daemonize(bool preforked, bool close_streams) {
    // if preforked=true, we are told we are already in a child
    // process that was forked before this function was called,
    // and so we don't need this first fork.
    if (!preforked) {
        switch (fork()) {
        case -1: return false;       /* error */
        case 0: break;               /* child */
        default: exit(EXIT_SUCCESS); /* parent */
        }
    }

    /* child carries on ...; note from this point on returning an error code
     * is useless as the original process will have already exited. Errors
     * must be reported via some other means (logging etc) */

    /* Become leader of a new session */
    if (setsid() == -1) {
        fprintf(stderr,
                "Failed daemonization. setsid() error: '%s'\n",
                strerror(errno));
        exit(EXIT_SUCCESS);
    }

    /* fork AGAIN to ensure the program can never reacquire
     * a controlling terminal, per SysV conventions */
    switch (fork()) {
    case -1:
        fprintf(stderr,
                "Faile daemonization. Error on 2nd fork(): '%s'\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    case 0: break; /* child (grandchild of orig process) should continue */
    default: exit(EXIT_SUCCESS);
    }

    /* clear umask; do not disallow any permissions */
    umask(0);

    /* cd to /, so as not to prevent shutdown by keeping the fs from being
     * unmounted */
    if (chdir("/") == -1) {
        fprintf(stderr,
                "daemonize(): failed to chdir() to '/': '%s'\n",
                strerror(errno));
    }

    if (!close_streams) {
        return true;
    }

    // attach all standard streams to /dev/null so that IO operations
    // don't fail (/dev/null can always be written to, discarding everything,
    // and can always be read from, always returning EOF).
    // Note we treat the following as non-fatal errors, and so we
    // still return success.
    int fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        fprintf(stderr,
                "daemonize(): failed to open /dev/null: '%s'\n",
                strerror(errno));
        return 0;
    }

    if (dup2(fd, STDIN_FILENO) != STDIN_FILENO) {
        fprintf(
          stderr,
          "daemonize(): failed to point stdin stream to /dev/null: '%s'\n",
          strerror(errno));
    }

    if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO) {
        fprintf(
          stderr,
          "daemonize(): failed to point stdout stream to /dev/null: '%s'\n",
          strerror(errno));
    }

    if (dup2(fd, STDERR_FILENO) != STDERR_FILENO) {
        fprintf(
          stderr,
          "daemonize(): failed to point stderr stream to /dev/null: '%s'\n",
          strerror(errno));
    }

    close(fd);

    return true; /* only grand-child of original process reaches here */
}

extern "C" {
struct result create_pidfile(const char *pidfile, bool ignore_exists) {
    int rc = -1;
    int fd = -1;
    const size_t BUFSZ = 100;
    char buf[BUFSZ];

    unsigned flags = 0;
    if (!ignore_exists) {
        flags |= O_EXCL;
    }

    // Always be the one to create the file, otherwise fail.
    fd = open(pidfile, O_RDWR | O_CREAT | flags, S_IRUSR | S_IWUSR);

    if (fd == -1) {
        return RESULT(false, "open()", errno);
    }

    struct result res;

    if (ftruncate(fd, 0) == -1) {
        res = RESULT(false, "ftruncate()", errno);
        goto error;
    }

    rc = snprintf(buf, BUFSZ, "%ld\n", static_cast<long>(getpid()));
    if (rc < 0 || static_cast<size_t>(rc) >= BUFSZ) {
        res = RESULT(false, "snprintf()", 0);
        goto error;
    }

    rc = write(fd, buf, strlen(buf));
    if (rc < 0) {
        res = RESULT(false, "write()", errno);
        goto error;
    } else if (static_cast<size_t>(rc) != strlen(buf)) {
        res = RESULT(false, "unexpected partial write", 0);
        goto error;
    }

    return RESULT(true, "", 0);

error:
    close(fd);
    return res;
}
}

std::pair<bool, std::string> create_pid_file(const std::string &pid_file_path,
                                             bool ignore_exists) {
    auto res = create_pidfile(pid_file_path.c_str(), ignore_exists);

    if (!res.ok) {
        return {false, geterr(res)};
    }

    return {true, ""};
}

std::pair<int, std::string> read_pid_file(const std::string &pid_file_path) {
    auto [content, err] = string_utils::load(pid_file_path);
    if (content.empty() && !err.empty()) {
        return {-1, err};
    }

    int pid = -1;
    try {
        pid = std::stoi(content);
    } catch (const std::exception &e) {
        return {-1,
                std::format("failed to convert contents {} to pid", content)};
    }

    return {pid, ""};
}
}  // namespace process
}  // namespace tarp
