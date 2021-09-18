#include <iostream>
#include <sstream>
#include <vector>
#include <unordered_map>

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <iomanip>

#include "vendor/linenoise/linenoise.h"

#include "register.hpp"

using namespace mini_debugger;

auto split = [](const auto& line, auto delimiter) {
    std::vector<std::string> out{};
    auto ss = std::stringstream(line);
    std::string item;

    while(std::getline(ss, item, delimiter)) {
        out.push_back(std::move(item));
    }
    return out;
};

auto is_prefix = [](const auto& s, const auto& of) {
    if(s.size() > of.size()) {
        return false;
    }
    return std::equal(s.begin(), s.end(), of.begin());
};

class Breakpoint {
public:
    explicit Breakpoint(pid_t pid, std::uintptr_t addr)
        :pid_(pid), addr_(addr) {}
    explicit Breakpoint(const Breakpoint& bp) = default;
    explicit Breakpoint(Breakpoint&& bp) = default;
    Breakpoint& operator=(const Breakpoint& bp) = default;
    Breakpoint& operator=(Breakpoint&& bp) = default;

    auto enable() {
        auto data = ptrace(PTRACE_PEEKDATA, pid_, addr_, nullptr);
        saved_data_ = static_cast<uint8_t>(data & 0xff);
        constexpr uint64_t int3 = 0xcc;
        uint64_t data_with_int3 = ((data & ~0xff) | int3);
        ptrace(PTRACE_POKEDATA, pid_, addr_, data_with_int3);
        enabled_ = true;
    }
    auto disable() {
        auto data = ptrace(PTRACE_PEEKDATA, pid_, addr_, nullptr);
        auto restored_data = ((data & ~0xff) | saved_data_);
        ptrace(PTRACE_POKEDATA, pid_, addr_, restored_data);
        enabled_ = false;
    }

    auto is_enabled() const { return enabled_; }
    auto get_address() const -> std::uintptr_t { return addr_; }

private:
    pid_t pid_;
    std::uintptr_t addr_;
    bool enabled_ = false;
    uint8_t saved_data_ = {};
};

class Debugger {
public:
    explicit Debugger(std::string_view prog_name,pid_t pid)
        :prog_name_(prog_name), pid_(pid) {}

    auto set_breakpoint_at(std::uintptr_t addr) {
        std::cout << "Set breakpoint at address 0x" << std::hex << addr << '\n';
        auto bp = Breakpoint(pid_, addr);
        bp.enable();
        breakpoints_.emplace(typename decltype(breakpoints_)::value_type{addr, bp});
    }

    auto wait_for_signal() {
        int wait_status;
        auto options = 0;
        waitpid(pid_, &wait_status, options);
    }

    auto step_over_breakpoint() -> void {
        auto possible_breakpoint_location = get_pc() - 1;
        if(breakpoints_.contains(possible_breakpoint_location)) {
            auto& bp = breakpoints_[possible_breakpoint_location];
            if(bp.is_enabled()) {
                auto previous_instruction_address = possible_breakpoint_location;
                set_pc(previous_instruction_address);
                bp.disable();
                ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
                wait_for_signal();
                bp.enable();
            }
        }
    }

    auto continue_execution() {
        step_over_breakpoint();
        ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
        wait_for_signal();
    }

    auto handle_command(const std::string& line) {
        auto args = split(line, ' ');
        const auto& command = args[0];

        if(is_prefix(command, std::string_view("continue"))) {
            continue_execution();
        }
        else if(is_prefix(command, std::string_view("break"))) {
            std::string addr(args[1], 2);
            set_breakpoint_at(std::stol(addr, 0, 16));
        }
        else if(is_prefix(command, std::string_view("register"))) {
            if(is_prefix(args[1], std::string_view("dump"))) {
                dump_registers();
            }
            else if(is_prefix(args[1], std::string_view("read"))) {
                std::cout << get_register_value(pid_, get_register_from(args[2])) << '\n';
            }
            else if(is_prefix(args[1], std::string_view("write"))) {
                std::string val(args[3], 2);
                set_register_value(pid_, get_register_from(args[2]), std::stol(val, 0 ,16));
            }
        }
        else if(is_prefix(command, std::string_view("memory"))) {
            std::string addr(args[2], 2);
            if(is_prefix(args[1], std::string_view("read"))) {
                std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << '\n';
            }
            else if(is_prefix(args[1], std::string_view("write"))) {
                std::string val(args[3], 2);
                write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
            }
        }
        else {
            std::cerr<< "Unknown command\n";
        }
    }

    auto run() {
        int wait_status;
        auto options = 0;
        waitpid(pid_, &wait_status, options);
        // Wait until child process was sent a SIGTRAP because of ptrace().

        char* line = nullptr;
        while((line = linenoise("minidgb> ")) != nullptr) {
            handle_command(line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
        }
    }

    auto dump_registers() const -> void {
        for(const auto& reg : register_descriptors) {
            std::cout << reg.name << " 0x"
                      << std::setfill('0') << std::setw(16)
                      << std::hex << get_register_value(pid_, reg.r)
                      << '\n';
        }
    }
    auto read_memory(uint64_t addr) const -> uint64_t {
        return ptrace(PTRACE_PEEKDATA, pid_, addr, nullptr);
    }
    auto write_memory(uint64_t addr, uint64_t value) -> void {
        ptrace(PTRACE_POKEDATA, pid_, addr, value);
    }
    auto get_pc() const -> uint64_t {
        return get_register_value(pid_, reg::rip);
    }
    auto set_pc(uint64_t value) -> void {
        set_register_value(pid_, reg::rip, value);
    }

private:
    std::string_view prog_name_;
    pid_t pid_;
    std::unordered_map<std::uintptr_t, Breakpoint> breakpoints_;
};

auto main(int argc, char* argv[]) -> int {
    if(argc < 2) {
        std::cerr<< "Program name not specified";
        return -1;
    }

    auto prog = argv[1];
    auto pid = fork();
    if(pid == 0) {
        // child process
        // execute debugee
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(prog, prog, nullptr);
    }
    else if (pid >= 1) {
        // parent process
        // execute debugger
        // pid == child process id
        std::cout<< "Started debugging process "<< pid << '\n';
        Debugger dbg(prog, pid);
        dbg.run();
    }
    return 0;
}