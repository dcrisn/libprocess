#pragma once

#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cmath>
#include <cstdint>
#include <cstring>

#include <tarp/math.h>

namespace tarp::utils::string_utils {

// Given an ascii character code, return its alias name as seen e.g. with `ascii
// -x` on linux.
std::optional<std::string>
ascii_charcode_to_alias_name(unsigned char asciichar);

// Given an ascii char alias name, return its char code value, as seen e.g. with
// `ascii -x` on linux.
std::optional<unsigned char>
ascii_alias_name_to_charcode(const std::string &alias);

// Read whole file into memory, split it into lines, and return a vector
// thereof.
std::vector<std::string> read_lines(const std::string &filepath,
                                    bool throw_on_failed_open = false);

// write the string s to fpath. All contents of fpath are discarded first and
// the file is created if it does not exist.
std::pair<bool, std::string> save(const std::string &fpath,
                                  const std::string &s);

// Read the file at path into memory as a string and return it.
// In case of error, return { "", <error string> }
std::pair<std::string, std::string> load(const std::string &path);

// Find the (0-based) indices in haystack where needle occurs.
std::vector<std::size_t> find_needle_positions(const std::string &haystack,
                                               const std::string &needle);

// Split the string s on the separator sep.
// If drop_empty_tokens=true, then if the tokens resulting from the split are
// empty strings, then they are discarded and only non-empty strings tokens are
// kept. Otherwise if drop_empty_tokens=false, all tokens, empty or not, are
// kept.
std::vector<std::string>
split(const std::string &s, const std::string &sep, bool drop_empty_tokens);

// Join all token strings into one single string, with each token separated by
// sep.
template<template<typename> class container = std::vector>
std::string join(const container<std::string> &tokens,
                 const std::string sep = " ");

// True if input matches against the regular expression pattern re, else False.
// The regular expression flavor/engine used is Extended POSIX. NOTE: the whole
// string must match, end to end.
bool match(const std::string input, const std::string re, bool case_sensitive);

// strip off all chars in characters if specified, otherwise all whitespace,
// from the right end of the input string.
std::string rstrip(const std::string &input,
                   const std::optional<std::string> &characters = {});

// strip off all chars in characters if specified, otherwise all whitespace,
// from the left end of the input string.
std::string lstrip(const std::string &input,
                   const std::optional<std::string> &characters = {});

// strip off all chars in characters if specified, otherwise all whitespace,
// from both the left and right ends of the input string.
std::string strip(const std::string &input,
                  const std::optional<std::string> &characters = {});

// Remove occurrences of substring in input. If n_first_occurrences=-1, all
// occurences are removed, else only (at most) n_first_occurrences.
std::string remove_substring(const std::string &input,
                             const std::string &substring,
                             int n_first_occurrences);

// Remove the prefix from the string if present.
std::string remove_prefix(const std::string &s,
                          const std::string &prefix,
                          bool case_sensitive);

// Remove the suffix from the string if present
std::string remove_suffix(const std::string &s,
                          const std::string &suffix,
                          bool case_sensitive);

// return the concatenation of n repetitions of input s;
// i.e.  s * n, as typical of higher-level languages.
// NOTE:
//   if n=0, an empty string is returned;
//   if n=1, the string is returned unchanged.
std::string repeat(const std::string &s, unsigned n);

// True if input is a base-10 integer of arbitrary width.
bool is_integer(const std::string &input);

// Convert input to an integer type T, if possible.
// The input string is stripped of whitespace at both ends before processing.
// If the resulting string contains non-(base 10) digits, the result will be
// empty.
template<typename T>
std::optional<T> to_integer(const std::string &input);

// Same as to_integer, but convert to a double.
std::optional<double> to_float(const std::string &input);

// If the string is a boolean (true/1 or false/0), convert it to a bool type.
// NOTE: the input string is stripped of whitespace and converted to
// all-lowercase before processing.
std::optional<bool> to_boolean(const std::string &s);

// True if the input is convertible to a bool, as described above.
bool is_boolean(const std::string &s);

// Return an all-lowercase version of s.
std::string to_lower(const std::string &s);

// Return an all-uppercase version of s.
std::string to_upper(const std::string &s);

// Return a copy of input with all occurences of pattern replaced with
// replacement. If use_regex=true, then pattern is taken to be an extended POSIX
// regular expression pattern instead of a plain string. If
// case_sensitive=false, then the pattern (irrespective of whether regex is used
// or not ) is matched without regard to case.
// NOTE: an optional is returned because an invalid regex pattern will cause the
// regex engine to throw.
std::optional<std::string> replace(const std::string &input,
                                   const std::string &pattern,
                                   const std::string &replacement,
                                   bool use_regex = false,
                                   bool case_sensitive = false);

// Return a copy of input with all occurrences of a replaced with b.
std::string replace_char(const std::string &input, char a, char b);

// If the vector returned has a size different from nbytes, then an error has
// occured and an error string will have been stored in error_string.
std::vector<std::uint8_t> get_n_bytes_from_hexstring(const std::string &s,
                                                     size_t nbytes,
                                                     std::string &error_string);

// Convert the string s to a vector of bytes. In case of error, this will be
// stored in error_string. s is expected to be a hexstring. That is, each two
// chars are taken to represent one byte. There must be no intervening
// whitespace. Leading and trailing whitespace is allowed and gets stripped
// automatically.
// Example valid input: a187da
std::vector<std::uint8_t> hexstring_to_bytes(const std::string &s,
                                             std::string &error_string);

template<typename T>
std::pair<std::optional<T>, std::string> hexstring_to_uint(const char *s);

template<typename T>
std::string int_to_hexstring(T i);

// Convert the byte array to a hexstring with no prefix. e.g. {1,255} will
// become {01ff}.
template<typename T>
std::string hexstring_from_bytes(const T &bytes);

// Return true if the string s only contains chars '1' and '0'.
// NOTE: assumes there is not whitespace etc.
inline bool is_bitstring(const std::string &s) {
    auto *str = s.c_str();
    for (unsigned i = 0; i < s.size(); ++i) {
        auto c = str[i];
        if (c != '0' and c != '1') {
            return false;
        }
    }
    return true;
}

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////

template<template<typename> class container>
std::string join(const container<std::string> &tokens, const std::string sep) {
    std::string result;
    auto len = tokens.size();

    for (size_t i = 0; i < len; ++i) {
        result.append(tokens[i]);

        // last (and first, of course) token is not followed by a sep
        if (i < (len - 1)) {
            result.append(sep);
        }
    }

    return result;
}

template<typename T>
std::optional<T> to_integer(const std::string &input) {
    static_assert(std::is_integral_v<T>);

    std::string s = tarp::utils::string_utils::strip(input);
    if (s.empty()) {
        return {};
    }

    errno = 0;

    // C++11 does not allow assigning string literals to char ** anymore;
    // this is just a way to work around that.
    char flag[1] = {'x'};
    char *marker = flag;
    long long converted = std::strtoll(s.c_str(), &marker, 10);

    // if marker was set to NUL by strtoll, it means the whole string
    // is valid (see man page). Therefore if this is not the case, either
    // the whole or part of the string is invalid.
    if (*marker != '\0') {
        return {};
    }

    // conversion overflows/underflows
    if (errno == ERANGE) {
        return {};
    }

    // ---- strtoll succeeds; but does converted fit into the type of T? ----

    using converted_type = decltype(converted);

    // CASE: converted is positive.
    if (converted >= 0) {
        if (static_cast<std::uintmax_t>(converted) <=
            std::numeric_limits<T>::max()) {
            return converted;
        }
    }
    // CASE: converted is negative.
    else if (std::numeric_limits<converted_type>::is_signed) {
        // cannot store input in output since input is signed and negative
        // while output is unsigned.
        if (std::numeric_limits<T>::is_signed) {
            if (std::numeric_limits<T>::min() <= converted) {
                return converted;
            }
        }
    }

    // converted does NOT fit into type T.
    return {};
}

// Clear num_digits_to_clear low-order digits from integer to base 10.
// Example:
// clear_lo_digits(1231245, 2) => 1231200.
template<typename T>
static inline T clear_lo_digits(T input, std::uint8_t num_digits_to_clear) {
    std::string s {std::to_string(input)};

    // clear all the digits --> avoid potential intpow wraparound
    // if the value of num_digits_to_clear is gt
    // std::numeric_limits<std::uint32_t>::max.
    if (num_digits_to_clear > s.size()) {
        return 0;
    }

    // Get number of bits needed to represent 10^m_num_digits.
    // log_2(x) = log_10(x) / log_10(2); here log_10(x) is obviously
    // simply m_num_digits, since log_10(10^m_num_digits) = m_num_digits.
    double num_bits_needed = std::ceil(num_digits_to_clear / std::log10(2.0f));

    double num_bits_avail = sizeof(T) * 8;
    if (num_bits_needed > num_bits_avail) {
        throw std::invalid_argument(
          "Excessive input values would cause wraparound");
    }

    unsigned divisor = tarp::math::intpow(10, num_digits_to_clear);

    // this will truncate the num_digits_to_clear leas-significant digits.
    // The division removes these digits; the multiplication reinserts
    // them, but zeroed.
    input = (input / divisor) * divisor;
    return input;
}

template<typename T>
std::pair<std::optional<T>, std::string> hexstring_to_uint(const char *s) {
    static_assert(std::is_integral_v<T> and std::is_unsigned_v<T>);

    if (!s) {
        return {{}, "invalid nullptr string argument"};
    }

    errno = 0;
    constexpr unsigned base = 16;
    char *endptr = nullptr;
    unsigned long res = strtoul(s, &endptr, base);

    if (errno != 0) {
        return {{}, strerror(errno)};
    }

    if (*endptr != '\0') {
        return {{}, "input not a hex number"};
    }

    if (res > std::numeric_limits<T>::max()) {
        return {{}, "result wider than T"};
    }

    return {static_cast<T>(res), ""};
}

template<typename T>
std::string int_to_hexstring(T i) {
    std::stringstream stream;

    // this whole song and dance here is needed because if T is a
    // char/std::uint8_t, the ascii representation will be used so we have
    // explicitly cast it to an int for std::hex to actually give us what we
    // want!
    constexpr std::size_t width = sizeof(T) * 2;
    static_assert(sizeof(T) <= sizeof(std::uint64_t));

    stream << std::setfill('0') << std::setw(width) << std::hex
           << static_cast<std::uint64_t>(i);
    return stream.str();
}

// Convert the byte array to a hexstring with no prefix. e.g. {1,255} will
// become {01ff}.
template<typename T>
std::string hexstring_from_bytes(const T &bytes) {
    using elem_t =
      typename std::remove_reference_t<decltype(bytes)>::value_type;
    static_assert(std::is_same_v<elem_t, std::uint8_t> or
                  std::is_same_v<elem_t, char> or
                  std::is_same_v<elem_t, unsigned char>);

    std::string s;
    for (auto byte : bytes) {
        s += string_utils::int_to_hexstring(byte);
    }
    return s;
}

}  // namespace tarp::utils::string_utils
