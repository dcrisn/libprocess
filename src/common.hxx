#pragma once

// copied from libtarp common.hxx

struct result {
    bool ok;
    const char *e;
    int errnum;
};

#define RESULT(ok, errstr, errnum) result{ok, errstr, errnum}

#include <cstring>
#include <string>
inline std::string geterr(const struct result res) {
    if (res.ok) {
        return "ok";
    }

    std::string err = res.e;

    if (res.errnum == 0) {
        return err;
    }

    // thread-safe strerror.
    char buff[256];
    memset(buff, 0, sizeof(buff));

#ifdef _GNU_SOURCE
    // the GNU version of strerror_r rather than the XSI one
    const char *errstr = strerror_r(res.errnum, buff, sizeof(buff));
#else
    strerror_r(res.errnum, buff, sizeof(buff));
    const char *errstr = buff;
#endif

    return err + ": " + errstr;
}
