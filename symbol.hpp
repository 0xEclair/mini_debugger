#include <string_view>

#include <elf/elf++.hh>

enum class symbol_type {
    notype,
    object,
    func,
    section,
    file
};

auto to_string(symbol_type st) -> std::string_view {
    switch(st) {
        case symbol_type::notype : return "notype" ;
        case symbol_type::object : return "object" ;
        case symbol_type::func   : return "func"   ;
        case symbol_type::section: return "section";
        case symbol_type::file   : return "file"   ;
        default: return "notype";
    }
}

struct symbol {
    symbol_type type;
    std::string name;
    std::uintptr_t addr;
};

auto to_symbol_type(elf::stt sym) {
    switch (sym) {
        case elf::stt::notype: return symbol_type::notype;
        case elf::stt::object: return symbol_type::object;
        case elf::stt::func: return symbol_type::func;
        case elf::stt::section: return symbol_type::section;
        case elf::stt::file: return symbol_type::file;
        default:return symbol_type::notype;
    }
}

auto lookup_symbol = [](elf::elf& elf, std::string_view name) {
    std::vector<symbol> syms;
    for(const auto& sec: elf.sections()) {
        if(sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym) {
            continue;
        }
        for(auto&& sym : sec.as_symtab()) {
            if(sym.get_name() == name) {
                auto& data = sym.get_data();
                syms.push_back(symbol{to_symbol_type(data.type()), sym.get_name(), data.value});
            }
        }
    }
    return syms;
};