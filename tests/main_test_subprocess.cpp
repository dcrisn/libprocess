// local dir
#include "string_utils.hxx"

// local project
#include "tarp/subprocess.hpp"

// 3rd Party
#include <asio/buffer.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

// c++ stdlib
#include <filesystem>
#include <iostream>
#include <thread>

using namespace std;
using namespace std::chrono_literals;
using namespace std::string_literals;

namespace proc = tarp::process;
namespace string_utils = tarp::utils::string_utils;
namespace fs = std::filesystem;

// TODO: test terminate() and async_terminate() as well.

TEST_CASE("Subprocess can be killed") {
    asio::io_context ioctx;
    std::vector<std::string> cmd = {"sleep", "5"};

    proc::subprocess p {ioctx, cmd, {}, false, 1s, {}};

    auto [ok, e] = p.run();
    if (!ok) {
        std::cerr << "Error: " << e << std::endl;
    }

    ioctx.run_for(2s);
    CHECK(p.killed() == true);
    CHECK(p.running() == false);
    CHECK(p.get_exit_status_string() == "killed");

    auto s = p.get_exit_status_string();
    std::cerr << "Exit: " << s << std::endl;
}

TEST_CASE("Subprocess can exit by itself without need for killing") {
    asio::io_context ioctx;
    std::vector<std::string> cmd = {"sleep", "2"};

    proc::subprocess p {ioctx, cmd, {}, false, 3s, {}};

    auto [ok, e] = p.run();
    if (!ok) {
        std::cerr << "Error: " << e << std::endl;
    }

    ioctx.run_for(5s);
    CHECK(p.killed() == false);
    CHECK(p.running() == false);
    CHECK(p.get_exit_code() == 0);

    auto s = p.get_exit_status_string();
    std::cerr << "Exit: " << s << std::endl;
}

TEST_CASE("CAN write to stdin and read from stdout") {
    asio::io_context ioctx;

    auto script = "while read -r LINE; do echo $LINE >&1; done";
    auto script_name = "test.sh";
    bool ok = false;
    std::string err;
    std::tie(ok, err) = string_utils::save(script_name, script);
    if (!ok) {
        std::cerr << "err: " << std::endl;
    }

    REQUIRE(ok == true);

    proc::writable_pipe w;
    proc::readable_pipe r;

    std::vector<std::string> cmd = {"bash", "./"s + script_name};
    proc::subprocess p {
      ioctx, cmd, {},
        false, 1s, {{w}, {r}, {nullptr}}
    };

    std::string string_to_write =
      "one two three four five six seven eight nine ten "
      "dfwefwfwfw few fwef ewf wf wfwe fwe fewf wfwef wef wfe wef wf \n";
    std::string string_written;
    std::string string_read;

    asio::posix::stream_descriptor sink(ioctx), source(ioctx);
    sink.assign(w.release());
    source.assign(r.release());

    std::string rbuff_raw;
    rbuff_raw.resize(65000);
    auto rbuff = asio::buffer(rbuff_raw);

    asio::async_write(
      sink, asio::buffer(string_to_write), [&](auto ec, size_t bytes_written) {
          std::cerr << "bytes written: " << bytes_written << std::endl;
          if (ec) {
              return;
          }
          string_written = string_to_write;
      });

    source.async_read_some(rbuff, [&](auto, size_t bytes_read) {
        std::cerr << "bytes read: " << bytes_read << ": " << rbuff_raw
                  << std::endl;
        string_read =
          std::string(rbuff_raw.begin(), rbuff_raw.begin() + bytes_read);
    });

    std::tie(ok, err) = p.run();
    if (!ok) {
        std::cerr << "Error: " << err << std::endl;
    }

    ioctx.run_for(2s);
    CHECK(p.running() == false);
    CHECK(string_to_write == string_written);
    CHECK(string_utils::rstrip(string_to_write) ==
          string_utils::rstrip(string_read));

    auto s = p.get_exit_status_string();
    std::cerr << "Exit: " << s << std::endl;
    fs::remove(script_name);
}

TEST_CASE("CAN keep stdout/stderr separate") {
    asio::io_context ioctx;

    const std::string STDOUT_STRING = "first";
    const std::string STDERR_STRING = "second";

    auto script = "echo -n " + STDOUT_STRING + ">&1";
    script += "; ";
    script += "echo -n " + STDERR_STRING + " >&2";
    auto script_name = "test.sh";

    bool ok = false;
    std::string err;
    std::tie(ok, err) = string_utils::save(script_name, script);
    if (!ok) {
        std::cerr << "err: " << std::endl;
    }

    REQUIRE(ok == true);

    proc::readable_pipe outstream, errstream;

    std::vector<std::string> cmd = {"bash", "./"s + script_name};

    proc::subprocess p {
      ioctx, cmd, {},
        false, 1s, {{nullptr}, {outstream}, {errstream}}
    };

    std::string string_read_stdout;
    std::string string_read_stderr;

    asio::posix::stream_descriptor stdout_source(ioctx), stderr_source(ioctx);
    stdout_source.assign(outstream.release());
    stderr_source.assign(errstream.release());

    std::string rbuff_raw_stdout;
    std::string rbuff_raw_stderr;
    rbuff_raw_stdout.resize(65000);
    rbuff_raw_stderr.resize(65000);
    auto rbuff_stdout = asio::buffer(rbuff_raw_stdout);
    auto rbuff_stderr = asio::buffer(rbuff_raw_stderr);

    stdout_source.async_read_some(rbuff_stdout, [&](auto, size_t bytes_read) {
        std::cerr << "bytes read: " << bytes_read << ": " << rbuff_raw_stdout
                  << std::endl;
        string_read_stdout = std::string(rbuff_raw_stdout.begin(),
                                         rbuff_raw_stdout.begin() + bytes_read);
        rbuff_raw_stdout.erase(rbuff_raw_stdout.begin() + bytes_read,
                               rbuff_raw_stdout.end());
    });

    stderr_source.async_read_some(rbuff_stderr, [&](auto, size_t bytes_read) {
        std::cerr << "bytes read: " << bytes_read << ": " << rbuff_raw_stderr
                  << std::endl;
        string_read_stderr = std::string(rbuff_raw_stderr.begin(),
                                         rbuff_raw_stderr.begin() + bytes_read);
        rbuff_raw_stderr.erase(rbuff_raw_stderr.begin() + bytes_read,
                               rbuff_raw_stderr.end());
    });

    std::tie(ok, err) = p.run();
    if (!ok) {
        std::cerr << "Error: " << err << std::endl;
    }

    ioctx.run_for(2s);
    CHECK(p.running() == false);

    std::cerr << "STDOUT_STRING: '" << STDOUT_STRING << "'" << std::endl;
    std::cerr << "STDERR_STRING: '" << STDERR_STRING << "'" << std::endl;
    std::cerr << "rbuff_raw_stdout: '" << rbuff_raw_stdout << "'" << std::endl;
    std::cerr << "rbuff_raw_stderr: '" << rbuff_raw_stderr << "'" << std::endl;
    CHECK(rbuff_raw_stdout == STDOUT_STRING);
    CHECK(rbuff_raw_stderr == STDERR_STRING);

    auto s = p.get_exit_status_string();
    std::cerr << "Exit: " << s << std::endl;
    fs::remove(script_name);
}

TEST_CASE("CAN join stdout/stderr together") {
    asio::io_context ioctx;

    const std::string STDOUT_STRING = "first";
    const std::string STDERR_STRING = "second";

    auto script = "echo -n " + STDOUT_STRING + ">&1";
    script += "; ";
    script += "echo -n " + STDERR_STRING + " >&2";
    auto script_name = "test.sh";

    bool ok = false;
    std::string err;
    std::tie(ok, err) = string_utils::save(script_name, script);
    if (!ok) {
        std::cerr << "err: " << std::endl;
    }

    REQUIRE(ok == true);

    proc::readable_pipe outstream;

    std::vector<std::string> cmd = {"bash", "./"s + script_name};

    proc::subprocess p {
      ioctx, cmd, {},
        false, 1s, {{nullptr}, {outstream}, {outstream}}
    };

    std::string string_read_stdout;

    asio::posix::stream_descriptor stdout_source(ioctx);
    stdout_source.assign(outstream.release());

    std::string rbuff_raw_stdout;
    rbuff_raw_stdout.resize(65000);
    auto rbuff_stdout = asio::buffer(rbuff_raw_stdout);

    stdout_source.async_read_some(rbuff_stdout, [&](auto, size_t bytes_read) {
        std::cerr << "bytes read: " << bytes_read << ": " << rbuff_raw_stdout
                  << std::endl;
        string_read_stdout = std::string(rbuff_raw_stdout.begin(),
                                         rbuff_raw_stdout.begin() + bytes_read);
        rbuff_raw_stdout.erase(rbuff_raw_stdout.begin() + bytes_read,
                               rbuff_raw_stdout.end());
    });

    std::tie(ok, err) = p.run();
    if (!ok) {
        std::cerr << "Error: " << err << std::endl;
    }

    ioctx.run_for(2s);
    CHECK(p.running() == false);

    std::cerr << "STDOUT_STRING: '" << STDOUT_STRING << "'" << std::endl;
    std::cerr << "rbuff_raw_stdout: '" << rbuff_raw_stdout << "'" << std::endl;
    CHECK(rbuff_raw_stdout == STDOUT_STRING + STDERR_STRING);

    auto s = p.get_exit_status_string();
    std::cerr << "Exit: " << s << std::endl;
}

TEST_CASE("Child process can read stdin and write it to file correctly") {
    asio::io_context ioctx;

    const std::string string_to_write = "this is the string to be written.\n";

    auto script = "while read -r LINE; do echo $LINE >&1; done";
    auto script_name = "test.sh";
    const std::string dst_file = "/tmp/myfile";
    const std::string dst_file2 = "/tmp/myfile.2";

    bool ok = false;
    std::string err;
    std::tie(ok, err) = string_utils::save(script_name, script);
    if (!ok) {
        std::cerr << "err: " << std::endl;
    }

    REQUIRE(ok == true);

    proc::writable_pipe instream;

    std::vector<std::string> cmd = {"bash", "./"s + script_name};

    proc::subprocess p {
      ioctx, cmd, {},
        false, 1s, {{instream}, {dst_file}, {}}
    };

    asio::posix::stream_descriptor sink(ioctx);
    sink.assign(instream.release());

    auto buff = asio::buffer(string_to_write);
    asio::async_write(sink, buff, [&](auto, size_t bytes_written) {
        std::cerr << "bytes written: " << bytes_written << std::endl;
    });

    std::tie(ok, err) = p.run();
    if (!ok) {
        std::cerr << "Error: " << err << std::endl;
    }

    ioctx.run_for(2s);
    CHECK(p.running() == false);

    auto [string_read, error_str] = string_utils::load(dst_file);
    if (error_str.empty() == false) {
        std::cerr << "Failed to load file: " << error_str << std::endl;
    }

    REQUIRE(error_str.empty());
    CHECK(string_read == string_to_write);

    proc::subprocess p2 {
      ioctx, cmd, {},
        false, 1s, {{dst_file}, {dst_file2}, {}}
    };
    std::tie(ok, err) = p2.wait();
    if (!ok) {
        std::cerr << "p2 Error: " << err << std::endl;
    }

    ioctx.run_for(2s);
    CHECK(p2.running() == false);

    std::tie(string_read, error_str) = string_utils::load(dst_file2);
    if (error_str.empty() == false) {
        std::cerr << "Failed to load file: " << error_str << std::endl;
    }
    REQUIRE(error_str.empty());
    CHECK(string_read == string_to_write);

    auto s = p.get_exit_status_string();
    std::cerr << "P Exit: " << s << std::endl;
    s = p2.get_exit_status_string();
    std::cerr << "P2 Exit: " << s << std::endl;

    fs::remove(script_name);
    fs::remove(dst_file);
    fs::remove(dst_file2);
}

// test that we can write to the stdin of Proc1 and read from the stdout of
// Proc3.
TEST_CASE("CAN pipe processes together") {
    asio::io_context ioctx;

    auto script = "while read -r LINE; do echo $LINE >&1; done";
    auto script_name = "test.sh";
    bool ok = false;
    std::string err;
    std::tie(ok, err) = string_utils::save(script_name, script);
    if (!ok) {
        std::cerr << "err: " << std::endl;
    }

    REQUIRE(ok == true);

    proc::writable_pipe sink;
    proc::readable_pipe source;
    proc::writable_pipe w1, w2;
    proc::readable_pipe r1, r2;

    std::string buff1;
    std::string buff2;
    std::string buff3;
    buff1.resize(2048);
    buff2.resize(2048);

    std::vector<std::string> cmd = {"bash", "./"s + script_name};
    // read from (the read end of the) sink, write to (the write end of) r1
    proc::subprocess p1 {
      ioctx, cmd, {},
        false, 1s, {{sink}, {r1}, {nullptr}}
    };

    // read from w1, write to r2
    proc::subprocess p2 {
      ioctx, cmd, {},
        false, 1s, {{w1}, {r2}, {nullptr}}
    };

    // read from w2, write to the source. We then read the final output from the
    // source.
    proc::subprocess p3 {
      ioctx, cmd, {},
        false, 1s, {{w2}, {source}, {nullptr}}
    };

    std::string string_to_write =
      "one two three four five six seven eight nine ten\n";
    std::string string_written;
    std::string string_read;
    string_read.resize(string_to_write.size());

    asio::posix::stream_descriptor source_stream1(ioctx), dst_stream1(ioctx);
    source_stream1.assign(r1.get_fd());
    dst_stream1.assign(w1.get_fd());

    asio::posix::stream_descriptor source_stream2(ioctx), dst_stream2(ioctx);
    source_stream2.assign(r2.get_fd());
    dst_stream2.assign(w2.get_fd());

    asio::posix::stream_descriptor initial_sink(ioctx), final_source(ioctx);
    initial_sink.assign(sink.get_fd());
    final_source.assign(source.get_fd());

    using T = asio::posix::stream_descriptor;

    // read some from the source and write to dst all that was read.
    std::function<void(T &, T &, std::string &)> read_from_write_to =
      [&](T &src, T &dst, std::string &buffer) {
          src.async_read_some(
            asio::buffer(buffer), [&](auto ec, size_t bytes_read) {
                if (ec) {
                    return;
                }

                buffer.erase(buffer.begin() + bytes_read, buffer.end());
                asio::async_write(
                  dst, asio::buffer(buffer), [&](auto ec2, size_t) {
                      if (ec2) {
                          return;
                      }
                      buffer.clear();
                      buffer.resize(2048);
                      read_from_write_to(src, dst, buffer);
                  });
            });
      };

    read_from_write_to(source_stream1, dst_stream1, buff1);
    read_from_write_to(source_stream2, dst_stream2, buff2);

    // write to the stdin of the first process
    asio::async_write(
      initial_sink, asio::buffer(string_to_write), [&](auto ec, size_t) {
          if (ec) {
              return;
          }
          string_written = string_to_write;
      });

    asio::async_read(
      final_source, asio::buffer(string_read), [&](auto ec, size_t) {
          if (ec) {
              return;
          }
      });

    std::tie(ok, err) = p1.run();
    if (!ok) {
        std::cerr << "Error p1: " << err << std::endl;
    }

    std::tie(ok, err) = p2.run();
    if (!ok) {
        std::cerr << "Error p2: " << err << std::endl;
    }

    std::tie(ok, err) = p3.run();
    if (!ok) {
        std::cerr << "Error p3: " << err << std::endl;
    }

    ioctx.run_for(2s);

    CHECK(p1.running() == false);
    CHECK(p2.running() == false);
    CHECK(p3.running() == false);

    // string written to the stdin of proc1 and read from the stdout of proc3
    std::cerr << "String to write: '" << string_to_write << "'" << std::endl;
    std::cerr << "String written: '" << string_written << "'" << std::endl;
    std::cerr << "String read: '" << string_read << "'" << std::endl;
    CHECK(string_written == string_to_write);
    CHECK(string_read == string_to_write);

    fs::remove(script_name);
}

TEST_CASE("Signal can be delivered to subprocess") {
    asio::io_context ioctx;

    std::string script = "num_signals_caught=0 \n\
OUTPUT_FILE=${1:?} \n\
\n\
handle_signal(){ \n\
    num_signals_caught=$((num_signals_caught+1)) \n\
    echo \"caught signal(${num_signals_caught}) !\" \n\
    echo -n $num_signals_caught > $OUTPUT_FILE \n\
} \n\
\n\
trap handle_signal SIGINT \n\
trap handle_signal SIGUSR1 \n\
\n\
while true; do sleep 1; echo still running...; done; echo script-done. \n\
      ";

    const std::string script_name = "/tmp/myscript";
    const std::string output_file = "/tmp/myscript.out";
    string_utils::save(script_name, script);
    std::vector<std::string> cmd = {"bash", script_name, " " + output_file};

    proc::subprocess p {ioctx, cmd, {}, false, {}, {}};

    auto [ok, e] = p.run();
    if (!ok) {
        std::cerr << "Error: " << e << std::endl;
    }

    // signals are not queued in linux, so we wait a good while to be more sure
    // they all get delivered.
    ioctx.run_for(2s);
    p.interrupt();
    std::this_thread::sleep_for(2s);
    p.interrupt();
    std::this_thread::sleep_for(2s);
    p.send_signal(SIGUSR1);
    std::this_thread::sleep_for(2s);
    p.send_signal(SIGUSR1);
    std::this_thread::sleep_for(2s);
    p.interrupt();
    std::this_thread::sleep_for(2s);
    p.send_signal(SIGKILL);  // terminate

    ioctx.run_for(4s);
    CHECK(p.killed() == true);
    CHECK(p.running() == false);

    auto [str_read, err_str] = string_utils::load(output_file);
    REQUIRE(err_str.empty());
    auto n = std::stoi(str_read);
    CHECK(n == 5);  // sent 5 signals

    auto s = p.get_exit_status_string();
    std::cerr << "Exit: " << s << std::endl;

    fs::remove(script_name);
    fs::remove(output_file);
}

int main(int argc, char *argv[]) {
    doctest::Context ctx;

    ctx.setOption("abort-after", 1);   // default - stop after 5 failed asserts
    ctx.applyCommandLine(argc, argv);  // apply command line - argc / argv
    ctx.setOption("no-breaks", true);  // override - don't break in the debugger

    int res = ctx.run();  // run test cases unless with --no-run

    if (ctx.shouldExit())  // query flags (and --exit) rely on this
    {
        return res;  // propagate the result of the tests
    }

    // your actual program execution goes here - only if we haven't exited

    return res;  // + your_program_res
}
