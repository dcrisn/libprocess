#include <cctype>
#include <fstream>
#include <iostream>
#include <optional>
#include <regex>
#include <set>

#include <tarp/string_utils.hxx>

using namespace std::string_literals;

namespace tarp {
namespace utils {
namespace string_utils {

namespace {

// NOTE: these descriptions are scraped straight from `ascii -a -x`.
static const std::map<std::uint8_t, std::string> ascii_char_to_alias {
  {0x00, "NUL" },
  {0x01, "SOH" },
  {0x02, "STX" },
  {0x03, "ETX" },
  {0x04, "EOT" },
  {0x05, "ENQ" },
  {0x06, "ACK" },
  {0x07, "BEL" },
  {0x08, "BS"  },
  {0x09, "HT"  },
  {0x0A, "LF"  },
  {0x0B, "VT"  },
  {0x0C, "FF"  },
  {0x0D, "CR"  },
  {0x0E, "SO"  },
  {0x0F, "SI"  },
  {0x10, "DLE" },
  {0x11, "DC1" },
  {0x12, "DC2" },
  {0x13, "DC3" },
  {0x14, "DC4" },
  {0x15, "NAK" },
  {0x16, "SYN" },
  {0x17, "ETB" },
  {0x18, "CAN" },
  {0x19, "EM"  },
  {0x1A, "SUB" },
  {0x1B, "ESC" },
  {0x1C, "FS"  },
  {0x1D, "GS"  },
  {0x1E, "RS"  },
  {0x1F, "US"  },
  {0x20, " "   },
  {0x21, "!"   },
  {0x22, R"(")"},
  {0x23, "#"   },
  {0x24, "$"   },
  {0x25, "%"   },
  {0x26, "&"   },
  {0x27, "'"   },
  {0x28, "("   },
  {0x29, ")"   },
  {0x2A, "*"   },
  {0x2B, "+"   },
  {0x2C, ","   },
  {0x2D, "-"   },
  {0x2E, "."   },
  {0x2F, "/"   },
  {0x30, "0"   },
  {0x31, "1"   },
  {0x32, "2"   },
  {0x33, "3"   },
  {0x34, "4"   },
  {0x35, "5"   },
  {0x36, "6"   },
  {0x37, "7"   },
  {0x38, "8"   },
  {0x39, "9"   },
  {0x3A, ":"   },
  {0x3B, ";"   },
  {0x3C, "<"   },
  {0x3D, "="   },
  {0x3E, ">"   },
  {0x3F, "?"   },
  {0x40, "@"   },
  {0x41, "A"   },
  {0x42, "B"   },
  {0x43, "C"   },
  {0x44, "D"   },
  {0x45, "E"   },
  {0x46, "F"   },
  {0x47, "G"   },
  {0x48, "H"   },
  {0x49, "I"   },
  {0x4A, "J"   },
  {0x4B, "K"   },
  {0x4C, "L"   },
  {0x4D, "M"   },
  {0x4E, "N"   },
  {0x4F, "O"   },
  {0x50, "P"   },
  {0x51, "Q"   },
  {0x52, "R"   },
  {0x53, "S"   },
  {0x54, "T"   },
  {0x55, "U"   },
  {0x56, "V"   },
  {0x57, "W"   },
  {0x58, "X"   },
  {0x59, "Y"   },
  {0x5A, "Z"   },
  {0x5B, "["   },
  {0x5C, R"(\)"},
  {0x5D, "]"   },
  {0x5E, "^"   },
  {0x5F, "_"   },
  {0x60, "`"   },
  {0x61, "a"   },
  {0x62, "b"   },
  {0x63, "c"   },
  {0x64, "d"   },
  {0x65, "e"   },
  {0x66, "f"   },
  {0x67, "g"   },
  {0x68, "h"   },
  {0x69, "i"   },
  {0x6A, "j"   },
  {0x6B, "k"   },
  {0x6C, "l"   },
  {0x6D, "m"   },
  {0x6E, "n"   },
  {0x6F, "o"   },
  {0x70, "p"   },
  {0x71, "q"   },
  {0x72, "r"   },
  {0x73, "s"   },
  {0x74, "t"   },
  {0x75, "u"   },
  {0x76, "v"   },
  {0x77, "w"   },
  {0x78, "x"   },
  {0x79, "y"   },
  {0x7A, "z"   },
  {0x7B, "{"   },
  {0x7C, "|"   },
  {0x7D, "}"   },
  {0x7E, "~"   },
  {0x7F, "DE"  },
};

static const std::map<std::string, std::uint8_t> ascii_alias_to_char {
  {"NUL",  0X00},
  {"SOH",  0X01},
  {"STX",  0X02},
  {"ETX",  0X03},
  {"EOT",  0X04},
  {"ENQ",  0X05},
  {"ACK",  0X06},
  {"BEL",  0X07},
  {"BS",   0X08},
  {"HT",   0X09},
  {"LF",   0X0A},
  {"VT",   0X0B},
  {"FF",   0X0C},
  {"CR",   0X0D},
  {"SO",   0X0E},
  {"SI",   0X0F},
  {"DLE",  0X10},
  {"DC1",  0X11},
  {"DC2",  0X12},
  {"DC3",  0X13},
  {"DC4",  0X14},
  {"NAK",  0X15},
  {"SYN",  0X16},
  {"ETB",  0X17},
  {"CAN",  0X18},
  {"EM",   0X19},
  {"SUB",  0X1A},
  {"ESC",  0X1B},
  {"FS",   0X1C},
  {"GS",   0X1D},
  {"RS",   0X1E},
  {"US",   0X1F},
  {" ",    0X20},
  {"!",    0X21},
  {R"(")", 0X22},
  {"#",    0X23},
  {"$",    0X24},
  {"%",    0X25},
  {"&",    0X26},
  {"'",    0X27},
  {"(",    0X28},
  {")",    0X29},
  {"*",    0X2A},
  {"+",    0X2B},
  {",",    0X2C},
  {"-",    0X2D},
  {".",    0X2E},
  {"/",    0X2F},
  {"0",    0X30},
  {"1",    0X31},
  {"2",    0X32},
  {"3",    0X33},
  {"4",    0X34},
  {"5",    0X35},
  {"6",    0X36},
  {"7",    0X37},
  {"8",    0X38},
  {"9",    0X39},
  {":",    0X3A},
  {";",    0X3B},
  {"<",    0X3C},
  {"=",    0X3D},
  {">",    0X3E},
  {"?",    0X3F},
  {"@",    0X40},
  {"A",    0X41},
  {"B",    0X42},
  {"C",    0X43},
  {"D",    0X44},
  {"E",    0X45},
  {"F",    0X46},
  {"G",    0X47},
  {"H",    0X48},
  {"I",    0X49},
  {"J",    0X4A},
  {"K",    0X4B},
  {"L",    0X4C},
  {"M",    0X4D},
  {"N",    0X4E},
  {"O",    0X4F},
  {"P",    0X50},
  {"Q",    0X51},
  {"R",    0X52},
  {"S",    0X53},
  {"T",    0X54},
  {"U",    0X55},
  {"V",    0X56},
  {"W",    0X57},
  {"X",    0X58},
  {"Y",    0X59},
  {"Z",    0X5A},
  {"[",    0X5B},
  {R"(\)", 0X5C},
  {"]",    0X5D},
  {"^",    0X5E},
  {"_",    0X5F},
  {"`",    0X60},
  {"a",    0X61},
  {"b",    0X62},
  {"c",    0X63},
  {"d",    0X64},
  {"e",    0X65},
  {"f",    0X66},
  {"g",    0X67},
  {"h",    0X68},
  {"i",    0X69},
  {"j",    0X6A},
  {"k",    0X6B},
  {"l",    0X6C},
  {"m",    0X6D},
  {"n",    0X6E},
  {"o",    0X6F},
  {"p",    0X70},
  {"q",    0X71},
  {"r",    0X72},
  {"s",    0X73},
  {"t",    0X74},
  {"u",    0X75},
  {"v",    0X76},
  {"w",    0X77},
  {"x",    0X78},
  {"y",    0X79},
  {"z",    0X7A},
  {"{",    0X7B},
  {"|",    0X7C},
  {"}",    0X7D},
  {"~",    0X7E},
  {"DE",   0X7F},
};
}  // namespace

std::optional<std::string>
ascii_charcode_to_alias_name(unsigned char asciichar) {
    auto found = ascii_char_to_alias.find(asciichar);
    if (found == ascii_char_to_alias.end()) {
        return {};
    }

    return found->second;
}

std::optional<unsigned char>
ascii_alias_name_to_charcode(const std::string &alias) {
    auto found = ascii_alias_to_char.find(alias);
    if (found == ascii_alias_to_char.end()) {
        return {};
    }

    return found->second;
}

namespace {
// NOTE: this function is just an alias to provide a more intuitive,
// self-documenting name for this use-case.
static inline auto find_split_points(const std::string &s,
                                     const std::string &sep) {
    return find_needle_positions(s, sep);
}

// Find the slice of string INPUT that starts at the leftmost non-matching
// character and ends at the rightmost nonmatching character. A matching
// character is:
// - any whitespace character, if characters is not specified
// - otherwise any character given in characters.
//
// @return a {s,e} pair of indices.
// - Both s and e are >= 0.
// - S is the start index (inclusive) and e is the end index of the slice
//   (exclusive). Therefore, in interval notation, the result is to be
//   interpreted as [s,e).
std::pair<size_t, size_t>
find_nonmatching_slice(const std::string &input,
                       const std::optional<std::string> &characters = {}) {
    if (input.empty()) {
        return {0, 0};  // empty string
    }

    std::string chars2strip = characters.value_or(""s);
    std::set<char> chars {chars2strip.begin(), chars2strip.end()};
    bool strip_whitespace = !characters.has_value();

    // Nothing to do: no whitespace to strip NOR anything else.
    if (!strip_whitespace && chars.empty()) {
        return {0, input.size()};  // intact input string
    }

    std::size_t end_index;
    std::size_t start_index;

    std::size_t len = input.size();

    // NOTE: beware of overflow here; strings should be of sensible length.
    // Absurdly long one-line minified files may cause UB.
    ssize_t j;
    std::size_t i;

    for (i = 0; i < len; ++i) {
        if (strip_whitespace) {
            if (!std::isspace(input[i])) {
                break;
            }
        } else if (!chars.count(input[i])) {
            // not one of the chars in set
            break;
        }
    }

    // string has been stripped of every char!
    if (i >= len) {
        return {0, 0};
    }

    // index of first non-matching char in input string.
    start_index = i;

    for (j = (len - 1); j >= 0; --j) {
        if (strip_whitespace) {
            if (!std::isspace(input[j])) break;
        } else if (!chars.count(input[j])) {
            // not one of the chars in set
            break;
        }
    }

    // string has been stripped of every char!
    if (j < 0) {
        return {0, 0};
    }
    // index *after* the last non-matching char.
    end_index = j + 1;

    if (start_index > end_index) {
        throw std::logic_error("Bad string slice: start_index > end_index!");
    }

    return {start_index, end_index};
}
}  // namespace

std::optional<std::string> replace_regex(const std::string &input,
                                         const std::string &pattern,
                                         const std::string &replacement,
                                         bool case_sensitive) {
    std::string result {input};

    auto flags = std::regex_constants::extended;
    if (!case_sensitive) {
        flags |= std::regex_constants::icase;
    }

    // stray escapes etc can cause an exception to be thrown
    try {
        std::regex_replace(result.begin(),
                           input.begin(),
                           input.end(),
                           std::regex(pattern, flags),
                           replacement);
    } catch (...) {
        return std::nullopt;
    }

    return result;
}

std::vector<std::string> read_lines(const std::string &filepath,
                                    bool throw_on_failed_open) {
    std::ifstream f(filepath);
    if (!f and throw_on_failed_open) {
        auto errmsg = "Failed to open file for reading: '"s + filepath + "'";
        throw std::invalid_argument(errmsg);
    }

    std::vector<std::string> lines;
    std::string line;

    while (std::getline(f, line)) {
        lines.push_back(line + "\n");
    }

    return lines;
}

std::vector<std::size_t> find_needle_positions(const std::string &haystack,
                                               const std::string &needle) {
    std::vector<std::size_t> needle_positions;
    if (needle.empty()) {
        return needle_positions;
    }

    std::size_t idx = 0;
    std::size_t len = haystack.size();

    while (idx < len) {
        auto pos = haystack.find(needle, idx);
        if (pos == std::string::npos) {
            break;
        }
        needle_positions.push_back(pos);
        idx = pos + 1;
    }

    return needle_positions;
}

std::vector<std::string>
split(const std::string &s, const std::string &sep, bool drop_empty_tokens) {
    std::vector<std::string> tokens;

    auto separator_positions = find_split_points(s, sep);
    std::size_t idx = 0;
    std::size_t string_len = s.size();

    for (auto split_pos : separator_positions) {
        if (idx >= string_len) break;

        std::size_t substring_len = split_pos - idx;
        if (!drop_empty_tokens or substring_len > 0) {
            tokens.push_back(s.substr(idx, substring_len));
        }

        idx = split_pos + 1;
    }

    // substring following the last split point
    if (idx < string_len) {
        std::size_t substring_len = string_len - idx;
        tokens.push_back(s.substr(idx, substring_len));
    }

    return tokens;
}

bool match(const std::string input, const std::string re, bool case_sensitive) {
    // NOTE: Extended POSIX regex flavor is used.
    auto flags =
      std::regex_constants::extended | std::regex_constants::optimize;
    if (!case_sensitive) {
        flags |= std::regex_constants::icase;
    }

    try {
        std::regex pattern(re, flags);
        std::smatch results;
        return regex_match(input, results, pattern);
    } catch (...) {
        return false;
    }
}

std::string rstrip(const std::string &input,
                   const std::optional<std::string> &characters) {
    auto [starti, endi] = find_nonmatching_slice(input, characters);
    return input.substr(0, endi);
}

std::string lstrip(const std::string &input,
                   const std::optional<std::string> &characters) {
    auto [starti, endi] = find_nonmatching_slice(input, characters);

    return input.substr(starti, input.size() - starti);
}

std::string strip(const std::string &input,
                  const std::optional<std::string> &characters) {
    return lstrip(rstrip(input, characters), characters);
}

std::string repeat(const std::string &s, unsigned n) {
    std::string result;
    for (unsigned i = 0; i < n; ++i) {
        result += s;
    }
    return result;
}

bool is_integer(const std::string &input) {
    std::string s = tarp::utils::string_utils::strip(input);
    if (s.empty()) {
        return false;
    }

    for (const auto &c : s) {
        if (!isdigit(c)) {
            return false;
        }
    }
    return true;
}

std::optional<double> to_float(const std::string &input) {
    std::string s = tarp::utils::string_utils::strip(input);
    if (s.empty()) {
        return {};
    }

    errno = 0;

    // C++11 does not allow assigning string literals to char ** anymore;
    // this is just a way to work around that.
    char flag[1] = {'x'};
    char *marker = flag;
    double converted = std::strtod(s.c_str(), &marker);

    // if marker was set to NUL by strtod, it means the whole string
    // is valid (see man page). Therefore if this is not the case, either
    // the whole or part of the string is invalid.
    if (*marker != '\0') {
        return {};
    }

    // conversion overflows/underflows
    if (errno == ERANGE) {
        return {};
    }

    return converted;
}

// Same as to_integer, but convert to a double.
std::optional<double> to_float(const std::string &input);

std::optional<bool> to_boolean(const std::string &s) {
    std::string input = tarp::utils::string_utils::strip(s);
    if (input.empty()) {
        return {};
    }

    std::transform(s.begin(), s.end(), input.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    if (input == "true" or input == "1") {
        return true;
    }
    if (input == "false" or input == "0") {
        return false;
    }

    return {};
}

bool is_boolean(const std::string &s) {
    return to_boolean(s).has_value();
}

std::string to_lower(const std::string &s) {
    std::string result {s};
    std::transform(s.begin(), s.end(), result.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return result;
}

std::string to_upper(const std::string &s) {
    std::string result {s};
    std::transform(s.begin(), s.end(), result.begin(), [](unsigned char c) {
        return std::toupper(c);
    });
    return result;
}

std::optional<std::string> replace(const std::string &input,
                                   const std::string &pattern,
                                   const std::string &replacement,
                                   bool use_regex,
                                   bool case_sensitive) {
    if (use_regex) {
        return replace_regex(input, pattern, replacement, case_sensitive);
    }

    std::string result;
    auto indices = case_sensitive ? find_needle_positions(input, pattern)
                                  : find_needle_positions(to_lower(input),
                                                          to_lower(pattern));
    auto patlen = pattern.size();

    std::size_t prev_end_index = 0;

    for (std::size_t idx : indices) {
        result += input.substr(prev_end_index, idx - prev_end_index);

        // skip the matched pattern and append replacement in its stead
        result += replacement;
        prev_end_index = idx + patlen;
    }

    result += input.substr(prev_end_index, input.size() - prev_end_index);

    return result;
}

std::string replace_char(const std::string &s, char a, char b) {
    std::string result {s};
    std::replace(result.begin(), result.end(), a, b);
    return result;
}

std::string remove_substring(const std::string &input,
                             const std::string &substring,
                             int n_first_occurrences) {
    auto split_positions = find_split_points(input, substring);

    std::size_t n {0};

    if (n_first_occurrences < 0) {
        n = split_positions.size();
    } else if (n_first_occurrences > 0) {
        n = std::min(static_cast<std::size_t>(n_first_occurrences),
                     split_positions.size());
    } else if (n_first_occurrences == 0) {
        return input;  // unchanged
    }

    std::string output {input};
    std::size_t n_chars_removed = 0;

    std::size_t substring_len = substring.size();
    for (unsigned i = 0; i < n; ++i) {
        std::size_t pos = split_positions[i] - n_chars_removed;
        output.erase(pos, substring_len);
        n_chars_removed += substring_len;
    }

    return output;
}

// Remove the prefix from the string if present.
std::string remove_prefix(const std::string &s,
                          const std::string &prefix,
                          bool case_sensitive) {
    auto check_equal_case_insensitive = [](auto a, auto b) {
        return (tolower(static_cast<char>(a)) == tolower(static_cast<char>(b)));
    };

    if (prefix.size() > s.size()) {
        return s;
    }

    auto substr = s.substr(0, prefix.size());

    if (!case_sensitive) {
        bool matches = std::equal(prefix.begin(),
                                  prefix.end(),
                                  s.begin(),
                                  check_equal_case_insensitive);
        if (matches) {
            return s.substr(prefix.size(), std::string::npos);
        }
    } else {
        bool matches = (substr == prefix);
        if (matches) {
            return s.substr(prefix.size(), std::string::npos);
        }
    }

    return s;
}

// Remove the suffix from the string if present
std::string remove_suffix(const std::string &s,
                          const std::string &suffix,
                          bool case_sensitive) {
    auto check_equal_case_insensitive = [](auto a, auto b) {
        return (tolower(static_cast<char>(a)) == tolower(static_cast<char>(b)));
    };

    if (suffix.size() > s.size()) {
        return s;
    }

    auto substr = s.substr(s.size() - suffix.size(), suffix.size());

    if (!case_sensitive) {
        bool matches = std::equal(suffix.begin(),
                                  suffix.end(),
                                  s.begin(),
                                  check_equal_case_insensitive);
        if (matches) {
            return s.substr(0, s.size() - suffix.size());
        }
    }

    else {
        bool matches = (substr == suffix);
        if (matches) {
            return s.substr(0, s.size() - suffix.size());
        }
    }

    return s;
}

std::vector<std::uint8_t>
get_n_bytes_from_hexstring(const std::string &s,
                           size_t nbytes,
                           std::string &error_string) {
    error_string = "";

    // each byte is encoded by two ASCII chars representing a hex number.
    const std::size_t expected_strlen = nbytes * 2;
    if (s.size() < expected_strlen) {
        throw std::invalid_argument(
          "Cannot parse bytes from hexstring - bad length");
    }

    std::vector<std::uint8_t> bytes;

    for (unsigned i = 0; i < nbytes; ++i) {
        // Extract byte as 2 character hex string
        std::string byte_str = s.substr(i * 2, 2);
        auto [res, err] = hexstring_to_uint<std::uint8_t>(byte_str.c_str());
        if (!res.has_value()) {
            std::cerr << "Error in data - invalid byte: " << byte_str << "!"
                      << std::endl;
            error_string = err;
            return {};
        }

        // std::cerr << "BYTE parsed: " << std::to_string( *res ) << std::endl;
        bytes.push_back(*res);
    }

    return bytes;
}

std::vector<std::uint8_t> hexstring_to_bytes(const std::string &s,
                                             std::string &error_string) {
    error_string.clear();

    std::string input = strip(s);

    // must be a multiple of 2
    if (input.size() % 2) {
        error_string = "bad hexstring";
        return {};
    }

    auto bytes =
      get_n_bytes_from_hexstring(input, input.size() / 2, error_string);
    if (bytes.size() != input.size() / 2) {
        if (error_string.empty()) {
            error_string = "bad parse";
        }
        return {};
    }

    return bytes;
}

std::pair<bool, std::string> save(const std::string &fpath,
                                  const std::string &s) {
    std::ofstream of;
    of.open(fpath, std::ios_base::out | std::ios_base::binary);
    if (!of.is_open()) {
        return {false, "failed to open "s + fpath};
    }

    of << s;
    of.flush();
    of.close();
    return {true, ""};
}

std::pair<std::string, std::string> load(const std::string &path) {
    std::ifstream f;
    f.open(path, std::ios_base::in | std::ios_base::binary);
    if (!f.is_open()) {
        return {"", "failed to open "s + path};
    }

    std::stringstream ss;
    ss << f.rdbuf();
    return {ss.str(), ""};
}


}  // namespace string_utils
}  // namespace utils
}  // namespace tarp
