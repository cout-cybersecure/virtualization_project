#include "vm_bridge.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstring>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

constexpr uint32_t kVmAbiVersion = 1;
constexpr size_t kMaxVmMessageLength = 4096;

enum class WorkerMode {
    InProcess,
    ForkSeccomp,
};

struct ExecutionPolicy {
    uint64_t max_instructions{100000};
    uint64_t max_memory_bytes{65536};
    uint64_t max_stack_bytes{4096};
    uint64_t timeout_ms{2000};
    std::string profile_name{"balanced"};
};

struct ExecutionRequest {
    std::filesystem::path bytecode_path;
    std::string instance_id{"local-dev"};
    bool json_output{false};
    WorkerMode worker_mode{WorkerMode::ForkSeccomp};
    ExecutionPolicy policy{};
};

struct LocalExecutionResult {
    VmResult vm_result{};
    std::string message{"no message"};
};

class ExecutionObserver {
  public:
    virtual ~ExecutionObserver() = default;
    virtual void on_started(const ExecutionRequest&) {}
    virtual void on_finished(const ExecutionRequest&, const VmResult&) {}
};

class NoopObserver final : public ExecutionObserver {};

std::vector<uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("failed to open bytecode file: " + path.string());
    }
    file.seekg(0, std::ios::end);
    const auto end_pos = file.tellg();
    if (end_pos < 0) {
        throw std::runtime_error("failed to determine bytecode size: " + path.string());
    }
    const auto size = static_cast<size_t>(end_pos);
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> bytes(size);
    if (size > 0) {
        file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (!file) {
            throw std::runtime_error("failed to read bytecode file: " + path.string());
        }
    }
    return bytes;
}

bool parse_u64(std::string_view text, uint64_t& out) {
    const char* begin = text.data();
    const char* end = begin + text.size();
    auto result = std::from_chars(begin, end, out);
    return result.ec == std::errc() && result.ptr == end;
}

std::string worker_mode_name(WorkerMode mode) {
    return mode == WorkerMode::ForkSeccomp ? "fork-seccomp" : "inproc";
}

void apply_profile(ExecutionPolicy& policy, std::string_view profile) {
    if (profile == "strict") {
        policy.max_instructions = 25000;
        policy.max_memory_bytes = 32768;
        policy.max_stack_bytes = 2048;
        policy.timeout_ms = 1000;
        policy.profile_name = "strict";
    } else if (profile == "research") {
        policy.max_instructions = 500000;
        policy.max_memory_bytes = 262144;
        policy.max_stack_bytes = 16384;
        policy.timeout_ms = 8000;
        policy.profile_name = "research";
    } else {
        policy.max_instructions = 100000;
        policy.max_memory_bytes = 65536;
        policy.max_stack_bytes = 4096;
        policy.timeout_ms = 2000;
        policy.profile_name = "balanced";
    }
}

std::optional<ExecutionRequest> parse_args(int argc, char** argv) {
    if (argc < 2) {
        return std::nullopt;
    }

    ExecutionRequest req{};
    req.bytecode_path = argv[1];
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--json") {
            req.json_output = true;
            continue;
        }
        if (arg == "--profile" && (i + 1) < argc) {
            apply_profile(req.policy, argv[++i]);
            continue;
        }
        if (arg == "--instance-id" && (i + 1) < argc) {
            req.instance_id = argv[++i];
            continue;
        }
        if (arg == "--worker-mode" && (i + 1) < argc) {
            const std::string mode = argv[++i];
            if (mode == "fork-seccomp") {
                req.worker_mode = WorkerMode::ForkSeccomp;
            } else if (mode == "inproc") {
                req.worker_mode = WorkerMode::InProcess;
            } else {
                return std::nullopt;
            }
            continue;
        }
        if (arg == "--max-instructions" && (i + 1) < argc) {
            uint64_t value = 0;
            if (!parse_u64(argv[++i], value)) {
                return std::nullopt;
            }
            req.policy.max_instructions = value;
            continue;
        }
        if (arg == "--max-memory" && (i + 1) < argc) {
            uint64_t value = 0;
            if (!parse_u64(argv[++i], value)) {
                return std::nullopt;
            }
            req.policy.max_memory_bytes = value;
            continue;
        }
        if (arg == "--max-stack" && (i + 1) < argc) {
            uint64_t value = 0;
            if (!parse_u64(argv[++i], value)) {
                return std::nullopt;
            }
            req.policy.max_stack_bytes = value;
            continue;
        }
        if (arg == "--timeout-ms" && (i + 1) < argc) {
            uint64_t value = 0;
            if (!parse_u64(argv[++i], value)) {
                return std::nullopt;
            }
            req.policy.timeout_ms = value;
            continue;
        }
        return std::nullopt;
    }
    return req;
}

void print_usage(const char* bin_name) {
    std::cerr << "Usage: " << bin_name << " <bytecode-file> [options]\n"
              << "  --profile <strict|balanced|research>\n"
              << "  --max-instructions <n>\n"
              << "  --max-memory <bytes>\n"
              << "  --max-stack <bytes>\n"
              << "  --timeout-ms <n>\n"
              << "  --worker-mode <fork-seccomp|inproc>\n"
              << "  --instance-id <id>\n"
              << "  --json\n";
}

std::string escape_json(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 8);
    for (char c : input) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

std::string extract_message(const VmResult& result) {
    if (result.message_ptr == nullptr || result.message_len == 0) {
        return "no message";
    }
    if (result.message_len > kMaxVmMessageLength) {
        return "invalid message length returned by VM core";
    }
    return std::string(result.message_ptr, result.message_len);
}

LocalExecutionResult execute_with_bytecode(const ExecutionRequest& req, const std::vector<uint8_t>& bytecode) {
    const VmConfig config{
        .max_instructions = req.policy.max_instructions,
        .max_memory_bytes = req.policy.max_memory_bytes,
        .max_stack_bytes = req.policy.max_stack_bytes,
        .vm_abi_version = kVmAbiVersion,
        .reserved_flags = 0,
    };

    LocalExecutionResult out{};
    out.vm_result = vm_execute_bytecode(bytecode.data(), bytecode.size(), config);
    out.message = extract_message(out.vm_result);
    return out;
}

LocalExecutionResult execute_in_process(const ExecutionRequest& req) {
    const std::vector<uint8_t> bytecode = read_file(req.bytecode_path);
    return execute_with_bytecode(req, bytecode);
}

struct WireResult {
    uint32_t status;
    int64_t exit_code;
    uint64_t instructions_executed;
    uint64_t peak_stack_bytes;
    uint64_t memory_touched_bytes;
    uint64_t message_len;
    char message[kMaxVmMessageLength];
};

bool write_all(int fd, const void* data, size_t len) {
    const auto* ptr = static_cast<const uint8_t*>(data);
    size_t offset = 0;
    while (offset < len) {
        const ssize_t written = ::write(fd, ptr + offset, len - offset);
        if (written <= 0) {
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return true;
}

bool read_all(int fd, void* data, size_t len) {
    auto* ptr = static_cast<uint8_t*>(data);
    size_t offset = 0;
    while (offset < len) {
        const ssize_t got = ::read(fd, ptr + offset, len - offset);
        if (got <= 0) {
            return false;
        }
        offset += static_cast<size_t>(got);
    }
    return true;
}

bool enable_seccomp_filter() {
    // Allow only syscalls needed for VM execution and result reporting.
    static const sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<uint32_t>(offsetof(struct seccomp_data, nr))),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_close, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_brk, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_munmap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mprotect, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_mremap, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigreturn, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sigaltstack, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_futex, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clock_gettime, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_set_tid_address, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_set_robust_list, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prlimit64, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_arch_prctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    static const sock_fprog prog{
        .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        .filter = const_cast<sock_filter*>(filter),
    };
    return ::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0;
}

int child_execute_and_report(const ExecutionRequest& req, int pipe_fd) {
    try {
        const std::vector<uint8_t> bytecode = read_file(req.bytecode_path);
        if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
            return 122;
        }
        if (!enable_seccomp_filter()) {
            return 123;
        }
        auto local = execute_with_bytecode(req, bytecode);
        WireResult wire{};
        wire.status = local.vm_result.status;
        wire.exit_code = local.vm_result.exit_code;
        wire.instructions_executed = local.vm_result.instructions_executed;
        wire.peak_stack_bytes = local.vm_result.peak_stack_bytes;
        wire.memory_touched_bytes = local.vm_result.memory_touched_bytes;
        wire.message_len = std::min(local.message.size(), kMaxVmMessageLength);
        std::memcpy(wire.message, local.message.data(), static_cast<size_t>(wire.message_len));
        if (!write_all(pipe_fd, &wire, sizeof(wire))) {
            return 121;
        }
        return 0;
    } catch (...) {
        WireResult wire{};
        wire.status = static_cast<uint32_t>(VM_STATUS_RUNTIME_ERROR);
        const std::string fallback = "worker failed before VM completion";
        wire.message_len = fallback.size();
        std::memcpy(wire.message, fallback.data(), fallback.size());
        write_all(pipe_fd, &wire, sizeof(wire));
        return 120;
    }
}

LocalExecutionResult execute_forked(const ExecutionRequest& req) {
    int pipefd[2] = {-1, -1};
    if (::pipe(pipefd) != 0) {
        throw std::runtime_error("failed to create worker pipe");
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        throw std::runtime_error("failed to fork worker");
    }
    if (pid == 0) {
        ::close(pipefd[0]);
        const int code = child_execute_and_report(req, pipefd[1]);
        ::close(pipefd[1]);
        _exit(code);
    }

    ::close(pipefd[1]);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(req.policy.timeout_ms);
    int status = 0;
    while (true) {
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            break;
        }
        if (waited < 0) {
            ::close(pipefd[0]);
            throw std::runtime_error("waitpid failed for worker");
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            ::kill(pid, SIGKILL);
            ::waitpid(pid, &status, 0);
            ::close(pipefd[0]);
            LocalExecutionResult timed_out{};
            timed_out.vm_result.status = VM_STATUS_SECURITY_VIOLATION;
            timed_out.vm_result.exit_code = -1;
            timed_out.message = "worker timed out and was killed";
            return timed_out;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    WireResult wire{};
    const bool got_wire = read_all(pipefd[0], &wire, sizeof(wire));
    ::close(pipefd[0]);

    LocalExecutionResult out{};
    if (!got_wire) {
        out.vm_result.status = VM_STATUS_RUNTIME_ERROR;
        out.vm_result.exit_code = -1;
        out.message = "failed to receive worker result";
        return out;
    }
    out.vm_result.status = wire.status;
    out.vm_result.exit_code = wire.exit_code;
    out.vm_result.instructions_executed = wire.instructions_executed;
    out.vm_result.peak_stack_bytes = wire.peak_stack_bytes;
    out.vm_result.memory_touched_bytes = wire.memory_touched_bytes;
    out.message.assign(wire.message, wire.message + std::min(wire.message_len, kMaxVmMessageLength));
    return out;
}

int run_request(const ExecutionRequest& req, ExecutionObserver& observer) {
    observer.on_started(req);
    LocalExecutionResult local{};
    try {
        if (req.worker_mode == WorkerMode::ForkSeccomp) {
            local = execute_forked(req);
        } else {
            local = execute_in_process(req);
        }
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 66;
    }
    observer.on_finished(req, local.vm_result);

    const auto& result = local.vm_result;
    const std::string& message = local.message;
    if (req.json_output) {
        std::ostringstream out;
        out << "{"
            << "\"instance_id\":\"" << escape_json(req.instance_id) << "\","
            << "\"profile\":\"" << escape_json(req.policy.profile_name) << "\","
            << "\"worker_mode\":\"" << worker_mode_name(req.worker_mode) << "\","
            << "\"status\":" << static_cast<int>(result.status) << ","
            << "\"exit_code\":" << result.exit_code << ","
            << "\"instructions\":" << result.instructions_executed << ","
            << "\"peak_stack_bytes\":" << result.peak_stack_bytes << ","
            << "\"memory_touched_bytes\":" << result.memory_touched_bytes << ","
            << "\"message\":\"" << escape_json(message) << "\""
            << "}\n";
        std::cout << out.str();
    } else {
        std::cout << "instance=" << req.instance_id
                  << " profile=" << req.policy.profile_name
                  << " worker_mode=" << worker_mode_name(req.worker_mode)
                  << " status=" << static_cast<int>(result.status)
                  << " exit_code=" << result.exit_code
                  << " instructions=" << result.instructions_executed
                  << " peak_stack_bytes=" << result.peak_stack_bytes
                  << " memory_touched_bytes=" << result.memory_touched_bytes
                  << " message=\"" << message << "\"\n";
    }

    return result.status == VM_STATUS_OK ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    auto maybe_req = parse_args(argc, argv);
    if (!maybe_req.has_value()) {
        print_usage(argv[0]);
        return 64;
    }

    NoopObserver observer;
    return run_request(*maybe_req, observer);
}
