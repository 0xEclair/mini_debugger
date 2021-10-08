#include <iostream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <fstream>

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <fcntl.h>

#include <linenoise.h>
#include <dwarf/dwarf++.hh>
#include <elf/elf++.hh>

#include "register.hpp"
#include "symbol.hpp"

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
    explicit Breakpoint() = default;
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
            :prog_name_(prog_name), pid_(pid) {
        auto fd = open(prog_name_.data(), O_RDONLY);
        elf_ = elf::elf(elf::create_mmap_loader(fd));
        dwarf_ = dwarf::dwarf(dwarf::elf::create_loader(elf_));
    }

    auto set_breakpoint_at(std::uintptr_t addr) {
        std::cout << "Set breakpoint at address 0x" << std::hex << addr << '\n';
        auto bp = Breakpoint(pid_, addr);
        bp.enable();
        breakpoints_.emplace(typename decltype(breakpoints_)::value_type{addr, bp});
    }

    auto set_breakpoint_at(std::string_view function) {
        for(const auto& cu : dwarf_.compilation_units()) {
            for(const auto& die : cu.root()) {
                if(die.has(dwarf::DW_AT::name) && dwarf::at_name(die) == function) {
                    auto low_pc = dwarf::at_low_pc(die);
                    auto le = line_entry_of(low_pc);
                    if(!le) {
                        return;
                    }
                    auto& line_entry = *le;
                    //code below will lead program to enter(intromit) first line of function implementation.
                    //++line_entry;
                    set_breakpoint_at(offset_of_dwarf(line_entry->address));
                }
            }
        }
    }

    auto set_breakpoint_at(std::string_view file, uint32_t line) {
        for(const auto& cu : dwarf_.compilation_units()) {
            auto is_suffix = [](auto s, auto of){
                if(s.size() > of.size()) {
                    return false;
                }
                auto diff = of.size() - s.size();
                return std::equal(s.begin(), s.end(), of.begin()+diff);
            };
            if(is_suffix(file, dwarf::at_name(cu.root()))) {
                const auto& lt = cu.get_line_table();
                for(const auto& entry : lt) {
                    if(entry.is_stmt && entry.line == line) {
                        set_breakpoint_at(offset_load_address(entry.address));
                        return;
                    }
                }
            }
        }
    }

    auto remove_breakpoint(std::uintptr_t addr) {
        if(breakpoints_.at(addr).is_enabled()) {
            breakpoints_.at(addr).disable();
        }
        breakpoints_.erase(addr);
    }

    auto last_signal() const {
        siginfo_t info;
        ptrace(PTRACE_GETSIGINFO, pid_, nullptr, &info);
        return info;
    }

    auto handle_sigtrap(siginfo_t signal) {
        switch(signal.si_code) {
            case SI_KERNEL:
            case TRAP_BRKPT: {
                set_pc(get_pc()-1);
                std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << '\n';
                auto offset = offset_load_address(get_pc());
                auto line_entry = line_entry_of(offset);
                if(line_entry) {
                    auto le = *line_entry;
                    print_source(le->file->path, le->line,3);
                }
                break;
            }
            case TRAP_TRACE: {
//#define TRACE_PRINT_SOURCE
#ifdef TRACE_PRINT_SOURCE
                std::cout << "Step at address 0x" << std::hex << get_pc() << '\n';
                auto offset = offset_load_address(get_pc());
                auto line_entry = line_entry_of(offset);
                if(line_entry) {
                    auto le = *line_entry;
                    print_source(le->file->path, le->line,3);
                }
#endif
                break;
            }
            default: {
                std::cout << "Unknown SIGTRAP code " << signal.si_code << '\n';
                break;
            }
        }
    }

    auto wait_for_signal() {
        int wait_status;
        auto options = 0;
        waitpid(pid_, &wait_status, options);

        auto signal = last_signal();
        switch(signal.si_signo) {
            case SIGTRAP: {
                handle_sigtrap(signal);
                break;
            }
            case SIGSEGV: {
                std::cout << "Yay, segfault. Reason: " << signal.si_code << '\n';
                break;
            }
            default: {
                std::cout << "Got signal " << strsignal(signal.si_signo) << '\n';
                break;
            }
        }
        // no need
//        if(WIFEXITED(wait_status)) {
//            std::cout << "Exited code:" << WEXITSTATUS(wait_status) << '\n';
//        }
//        if(WIFSIGNALED(wait_status)) {
//            std::cout << "Terminated code:" << WTERMSIG(wait_status) << '\n';
//        }
//        if(WIFSTOPPED(wait_status)) {
//            std::cout << "Stopped code:" << WSTOPSIG(wait_status) << '\n';
//        }
    }

    auto single_step_instruction() {
        ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
        wait_for_signal();
    }

    auto single_step_instruction_with_breakpoint_check() {
        if(breakpoints_.contains(get_pc())) {
            step_over_breakpoint();
        }
        else {
            single_step_instruction();
        }
    }

    auto step_over_breakpoint() -> void {
        auto pc = get_pc();
        if(breakpoints_.contains(pc)) {
            auto& bp = breakpoints_[pc];
            if(bp.is_enabled()) {
                bp.disable();
                single_step_instruction();
                bp.enable();
            }
        }
    }

    auto step_out() {
        auto frame_pointer = get_register_value(pid_, reg::rbp);
        auto return_address = read_memory(frame_pointer + 8);
        auto need_remove_breakpoint = false;
        if(!breakpoints_.contains(return_address)) {
            set_breakpoint_at(return_address);
            need_remove_breakpoint = true;
        }
        continue_execution();
        if(need_remove_breakpoint) {
            remove_breakpoint(return_address);
        }
    }

    auto step_in() {
        auto le = line_entry_of(offset_load_address(get_pc()));
        if(!le) {
            std::cout << "No entry at pc:" << std::hex << get_pc() << '\n';
            return;
        }
        auto line = (*le)->line;
        for(auto tmp = line_entry_of(offset_load_address(get_pc())); tmp ;) {
            if((*tmp)->line != line) {
                break;
            }
            single_step_instruction_with_breakpoint_check();
            tmp = line_entry_of(offset_load_address(get_pc()));
        }

        le = line_entry_of(offset_load_address(get_pc()));
        if(le) {
            auto& line_entry = *le;
            print_source(line_entry->file->path, line_entry->line, 3);
        }
    }

    auto step_over() {
        auto func = function_of(offset_load_address(get_pc()));
        if(!func) {
            return ;
        }

        auto func_entry = at_low_pc(*func);
        auto func_end = at_high_pc(*func);

        auto le = line_entry_of(func_entry);
        if(!le) {
            return ;
        }
        auto& line_entry = *le;

        auto sl = line_entry_of(get_pc());
        if(!sl) {
            return ;
        }
        auto& start_line = *sl;

        std::vector<std::uintptr_t> to_delete{};
        while(line_entry->address < func_end) {
            auto load_address = offset_of_dwarf(line_entry->address);
            if(line_entry->address != start_line->address && !breakpoints_.contains(load_address)) {
                set_breakpoint_at(load_address);
                to_delete.push_back(load_address);
            }
            ++line_entry;
        }

        auto frame_point = get_register_value(pid_, reg::rbp);
        auto return_address = read_memory(frame_point + 8);
        if(!breakpoints_.contains(return_address)) {
            set_breakpoint_at(return_address);
            to_delete.push_back(return_address);
        }
        continue_execution();
        for(auto addr : to_delete) {
            remove_breakpoint(addr);
        }
    }

    auto continue_execution() -> void {
        step_over_breakpoint();
        ptrace(PTRACE_CONT, pid_, nullptr, nullptr);
        wait_for_signal();
    }

    auto handle_command(const std::string& line) {
        if(line == "") {
            return ;
        }
        auto args = split(line, ' ');
        const auto& command = args[0];

        if(is_prefix(command, cmd::continue_running)) {
            continue_execution();
        }
        else if(is_prefix(command, cmd::breakpoint)) {
            if(args[1][0] == '0' && args[1][1] == 'x') {
                std::string addr(args[1],2);
                set_breakpoint_at(std::stol(addr, 0, 16));
            }
            else if(args[1].find(':') != std::string::npos) {
                auto file_and_line = split(args[1], ':');
                set_breakpoint_at(file_and_line[0], std::stoi(file_and_line[1]));
            }
            else {
                set_breakpoint_at(args[1]);
            }
        }
        else if(is_prefix(command, cmd::reg)) {
            if(is_prefix(args[1], cmd::dump)) {
                dump_registers();
            }
            else if(is_prefix(args[1], cmd::read)) {
                std::cout << get_register_value(pid_, get_register_from(args[2])) << '\n';
            }
            else if(is_prefix(args[1], cmd::write)) {
                std::string val(args[3], 2);
                set_register_value(pid_, get_register_from(args[2]), std::stol(val, 0 ,16));
            }
        }
        else if(is_prefix(command, cmd::memory)) {
            std::string addr(args[2], 2);
            if(is_prefix(args[1], cmd::read)) {
                std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << '\n';
            }
            else if(is_prefix(args[1], cmd::write)) {
                std::string val(args[3], 2);
                write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
            }
        }
        else if(is_prefix(command, cmd::single_step_instruction)) {
            single_step_instruction_with_breakpoint_check();
        }
        else if(is_prefix(command, cmd::step_out)) {
            step_out();
        }
        else if(is_prefix(command, cmd::step_in)) {
            step_in();
        }
        else if(is_prefix(command, cmd::step_over)) {
            step_over();
        }
        else if(is_prefix(command, cmd::symbol)) {
            auto syms = lookup_symbol(elf_, args[1]);
            for(const auto& s : syms) {
                std::cout << s.name << ' '
                          << to_string(s.type) << " 0x" << std::hex << s.addr << '\n';
            }
        }
        else {
            std::cerr<< "Unknown command\n";
        }
    }

    auto initialize_load_address() {
        if(elf_.get_hdr().type == elf::et::dyn) {
            std::ifstream map("/proc/" + std::to_string(pid_) + "/maps");
            std::string addr;
            std::getline(map, addr, '-');
            load_address_ = std::stoi(addr, 0, 16);
        }
    }

    auto run() {
        wait_for_signal();
        // Wait until child process was sent a SIGTRAP because of ptrace().
        initialize_load_address();

        char* line = nullptr;
        while((line = linenoise("dbg> ")) != nullptr) {
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
    auto function_of(uint64_t pc) -> std::optional<dwarf::die> {
        for(auto& cu : dwarf_.compilation_units()) {
            if(die_pc_range(cu.root()).contains(pc)) {
                for(auto& die : cu.root()) {
                    if(die.tag == dwarf::DW_TAG::subprogram) {
                        if(die_pc_range(die).contains(pc)) {
                            return die;
                        }
                    }
                }
            }
        }
        std::cerr << "Cannot find function.";
        return {};
    }
    auto line_entry_of(uint64_t pc) -> std::optional<dwarf::line_table::iterator> {
        for(auto& cu : dwarf_.compilation_units()) {
            if(die_pc_range(cu.root()).contains(pc)) {
                auto& lt = cu.get_line_table();
                auto res = lt.find_address(pc);
                if(res == lt.end()) {
                    break;
                }
                else {
                    return res;
                }
            }
        }
        std::cerr << "Cannot find line entry\n";
        return {};
    }

    auto offset_load_address(uint64_t addr) -> uint64_t {
        return addr - load_address_;
    }

    auto offset_of_dwarf(uint64_t addr) -> uint64_t {
        return addr + load_address_;
    }

    auto print_source(std::string_view file_name, unsigned line, unsigned n_lines_context) -> void {
        std::ifstream file(file_name.data());
        auto start_line = line <= n_lines_context ? 1 : line-n_lines_context;
        auto end_line = line + n_lines_context + (line < n_lines_context? n_lines_context - line : 0);
        char c{};
        auto current_line = 1u;
        while(current_line != start_line && file.get(c)) {
            if(c == '\n') {
                ++current_line;
            }
        }
        std::cout << '\n'
                  << (current_line == line? "> " : "  ");
        while(current_line <= end_line && file.get(c)) {
            std::cout << c;
            if(c == '\n') {
                ++current_line;
                std::cout << (current_line == line? "> " : "  ");
            }
        }
        std::cout << '\n';
    }

public:
    class Command {
    public:
        constexpr static std::string_view continue_running= {"continue"};
        constexpr static std::string_view breakpoint = {"breakpoint"};
        constexpr static std::string_view reg = {"register"};
        constexpr static std::string_view dump = {"dump"};
        constexpr static std::string_view read = {"read"};
        constexpr static std::string_view write = {"write"};
        constexpr static std::string_view memory = {"memory"};
        constexpr static std::string_view single_step_instruction = {"singlestep"};
        constexpr static std::string_view step_out = {"stout"};
        constexpr static std::string_view step_in = {"stin"};
        constexpr static std::string_view step_over = {"stover"};
        constexpr static std::string_view symbol = {"symbol"};
    };
    using cmd = Command;

private:
    std::string_view prog_name_;
    pid_t pid_;
    std::unordered_map<std::uintptr_t, Breakpoint> breakpoints_;
    dwarf::dwarf dwarf_;
    elf::elf elf_;
    uint64_t load_address_{};
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