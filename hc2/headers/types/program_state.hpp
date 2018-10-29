//===----------------------------------------------------------------------===//
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#pragma once

#include "raii_handle.hpp"
#include "../functions/integer_computational_basis.hpp"
#include "../functions/hsa_interfaces.hpp"
#include "../types/code_object_bundle.hpp"

#include <hc.hpp>

#include <hsa/hsa.h>
#include <hsa/hsa_ext_amd.h>

#include "../../external/elfio/elfio.hpp"

#include <link.h>

#include <cstddef>
#include <iterator>
#include <mutex>
#include <ostream>
#include <sstream>
#include <string>
#include <unordered_map>

namespace hc2
{
    namespace
    {
        using RAII_code_object_reader =
            RAII_move_only_handle<
                hsa_code_object_reader_t,
                decltype(hsa_code_object_reader_destroy)*>;
        using RAII_executable = RAII_move_only_handle<
            hsa_executable_t, decltype(hsa_executable_destroy)*>;

        inline
        RAII_code_object_reader make_code_object_reader(
            const char* f, std::size_t n)
        {
            RAII_code_object_reader r{{}, hsa_code_object_reader_destroy};

            if (positive(n)) {
                throwing_hsa_result_check(
                    hsa_code_object_reader_create_from_memory(f, n, &handle(r)),
                    __FILE__,
                    __func__,
                    __LINE__);
            }

            return r;
        }

        inline
        RAII_code_object_reader make_code_object_reader(
            const std::vector<char>& x)
        {
            return make_code_object_reader(x.data(), x.size());
        }

struct Symbol {
    std::string name;
    ELFIO::Elf64_Addr value = 0;
    ELFIO::Elf_Xword size = 0;
    ELFIO::Elf_Half sect_idx = 0;
    uint8_t bind = 0;
    uint8_t type = 0;
    uint8_t other = 0;
};

inline Symbol read_symbol(const ELFIO::symbol_section_accessor& section, unsigned int idx) {
    assert(idx < section.get_symbols_num());

    Symbol r;
    section.get_symbol(idx, r.name, r.value, r.size, r.bind, r.type, r.sect_idx, r.other);

    return r;
}
        template <typename P>
        static
        inline ELFIO::section* find_section_if(ELFIO::elfio& reader, P p) {
            const auto it = std::find_if(reader.sections.begin(), reader.sections.end(), std::move(p));
            return it != reader.sections.end() ? *it : nullptr;
        }

inline
const std::unordered_map<std::string, std::pair<ELFIO::Elf64_Addr, ELFIO::Elf_Xword>>&
symbol_addresses() {
    static std::unordered_map<std::string, std::pair<ELFIO::Elf64_Addr, ELFIO::Elf_Xword>> r;
    static std::once_flag f;

    std::call_once(f, []() {
        dl_iterate_phdr(
            [](dl_phdr_info* info, size_t, void*) {
                static constexpr const char self[] = "/proc/self/exe";
                ELFIO::elfio reader;

                static unsigned int iter = 0u;
                if (reader.load(!iter ? self : info->dlpi_name)) {
                    auto it = find_section_if(
                        reader, [](const class ELFIO::section* x) { return x->get_type() == SHT_SYMTAB; });

                    if (it) {
                        const ELFIO::symbol_section_accessor symtab{reader, it};

                        for (auto i = 0u; i != symtab.get_symbols_num(); ++i) {
                            auto tmp = read_symbol(symtab, i);

                            if (tmp.type == STT_OBJECT && tmp.sect_idx != SHN_UNDEF) {
                                const auto addr = tmp.value + (iter ? info->dlpi_addr : 0);
                                r.emplace(std::move(tmp.name), std::make_pair(addr, tmp.size));
                            }
                        }
                    }

                    ++iter;
                }

                return 0;
            },
            nullptr);
    });

    return r;
}

inline
std::unordered_map<std::string, void*>& globals() {
    static std::unordered_map<std::string, void*> r;
    static std::once_flag f;
    std::call_once(f, []() { r.reserve(symbol_addresses().size()); });

    return r;
}

inline
std::vector<std::string> copy_names_of_undefined_symbols(const ELFIO::symbol_section_accessor& section) {
    std::vector<std::string> r;

    for (auto i = 0u; i != section.get_symbols_num(); ++i) {
        // TODO: this is boyscout code, caching the temporaries
        //       may be of worth.

        auto tmp = read_symbol(section, i);
        if (tmp.sect_idx == SHN_UNDEF && !tmp.name.empty()) {
            r.push_back(std::move(tmp.name));
        }
    }

    return r;
}

inline
void associate_code_object_symbols_with_host_allocation(const ELFIO::elfio& reader,
                                                        ELFIO::section* code_object_dynsym,
                                                        hsa_agent_t agent,
                                                        hsa_executable_t& executable) {
    if (!code_object_dynsym) return;

    const auto undefined_symbols =
        copy_names_of_undefined_symbols(ELFIO::symbol_section_accessor{reader, code_object_dynsym});

    for (auto&& x : undefined_symbols) {
        if (globals().find(x) != globals().cend()) return;

        const auto it1 = symbol_addresses().find(x);

        if (it1 == symbol_addresses().cend()) {
            throw std::runtime_error{"Global symbol: " + x + " is undefined."};
        }

        static std::mutex mtx;
        std::lock_guard<std::mutex> lck{mtx};

        if (globals().find(x) != globals().cend()) return;
        globals().emplace(x, (void*)(it1->second.first));
        void* p = nullptr;
        hsa_amd_memory_lock(reinterpret_cast<void*>(it1->second.first), it1->second.second,
                            nullptr,  // All agents.
                            0, &p);

        hsa_executable_agent_global_variable_define(executable, agent, x.c_str(), p);
    }
}

void load_code_object_and_freeze_executable(
    const std::string& file, hsa_agent_t agent,
    hsa_executable_t
        executable) {  // TODO: the following sequence is inefficient, should be refactored
    //       into a single load of the file and subsequent ELFIO
    //       processing.
    static const auto cor_deleter = [](hsa_code_object_reader_t* p) {
        if (p) {
            hsa_code_object_reader_destroy(*p);
            delete p;
        }
    };

    using RAII_code_reader = std::unique_ptr<hsa_code_object_reader_t, decltype(cor_deleter)>;

    if (!file.empty()) {
        RAII_code_reader tmp{new hsa_code_object_reader_t, cor_deleter};
        hsa_code_object_reader_create_from_memory(file.data(), file.size(), tmp.get());

        hsa_executable_load_agent_code_object(executable, agent, *tmp, nullptr, nullptr);

        hsa_executable_freeze(executable, nullptr);

        static std::vector<RAII_code_reader> code_readers;
        static std::mutex mtx;

        std::lock_guard<std::mutex> lck{mtx};
        code_readers.push_back(move(tmp));
    }
}





        inline
        RAII_executable executable(
            const std::vector<char>& blob, hsa_agent_t agent)
        {
            RAII_executable r{{}, hsa_executable_destroy};

            std::string blob_to_str{blob.cbegin(), blob.cend()};
            std::stringstream blob_is{blob_to_str};
            ELFIO::elfio reader;

            if (!reader.load(blob_is)) return r;
 
            const auto code_object_dynsym = find_section_if(
                reader, [](const ELFIO::section* x) { return x->get_type() == SHT_DYNSYM; });

            hsa_executable_create_alt(
                HSA_PROFILE_FULL,
                HSA_DEFAULT_FLOAT_ROUNDING_MODE_DEFAULT, nullptr,
                &handle(r));

            associate_code_object_symbols_with_host_allocation(reader, code_object_dynsym, agent,
                                                               handle(r));

            load_code_object_and_freeze_executable(blob_to_str, agent, handle(r));
            return r;
        }

#if 0
        inline
        RAII_executable executable(
            const RAII_code_object_reader& x, hsa_agent_t a)
        {
            RAII_executable r{{}, hsa_executable_destroy};

            throwing_hsa_result_check(
                hsa_executable_create_alt(
                    HSA_PROFILE_FULL,//hsa_agent_profile(av) - TODO: this is a bug.
                    hsa_agent_float_rounding_mode(a),
                    nullptr,
                    &handle(r)),
                __FILE__,
                __func__,
                __LINE__);

            throwing_hsa_result_check(
                hsa_executable_load_agent_code_object(
                    handle(r), a, handle(x), nullptr, nullptr),
                __FILE__,
                __func__,
                __LINE__);

            // TODO: temporary.
            std::uint32_t v = UINT32_MAX;
            throwing_hsa_result_check(
                hsa_executable_validate_alt(handle(r), nullptr, &v),
                __FILE__,
                __func__,
                __LINE__);

            assert(zero(v));

            throwing_hsa_result_check(
                hsa_executable_freeze(handle(r), nullptr),
                __FILE__,
                __func__,
                __LINE__);

            return r;
        }
#endif
    }

    class Program_state {
/*
        using Code_object_table = std::unordered_map<
            hsa_isa_t, std::vector<RAII_code_object_reader>>;
*/
        using Code_object_table = std::unordered_map<
            hsa_isa_t, std::vector<std::vector<char>>>;

        using Executable_table = std::unordered_map<
            hsa_agent_t, std::vector<RAII_executable>>;
        using Kernel_table = std::unordered_map<
            hsa_agent_t, std::vector<hsa_executable_symbol_t>>;

        friend const Program_state& program_state();

        friend
        inline
        const Kernel_table& kernels(const Program_state& x)
        {
            return x.kernel_table_();
        }

        friend
        inline
        const Executable_table& executable_table(const Program_state& x)
        {
            return x.executable_table_();  
        }

        std::vector<hc::accelerator> acc_;

#if 0
        template <typename P>
        static
        inline ELFIO::section* find_section_if(ELFIO::elfio& reader, P p) {
            const auto it = std::find_if(reader.sections.begin(), reader.sections.end(), std::move(p));
            return it != reader.sections.end() ? *it : nullptr;
        }
#endif

        template<typename T = std::vector<std::vector<char>>>
        static
        int copy_kernel_sections_(dl_phdr_info* x, size_t, void* kernels)
        {
            static constexpr const char kernel[] = ".kernel";

            auto out = static_cast<T*>(kernels);

            ELFIO::elfio tmp;
            if (tmp.load(x->dlpi_name)) {
                for (auto&& y : tmp.sections) {
                    if (y->get_name() == kernel) {
                        out->emplace_back(
                            y->get_data(), y->get_data() + y->get_size());
                    }
                }
            }

            return 0;
        }

        static
        const std::vector<Bundled_code_header>& kernel_sections_()
        {
            static std::vector<Bundled_code_header> r;
            static std::once_flag f;
            std::call_once(f, []() {
                std::vector<std::vector<char>> ks;

                static constexpr const char self[] = "/proc/self/exe";
                static constexpr const char kernel_section[] = ".kernel";
                ELFIO::elfio reader;
                if (!reader.load(self)) {
                    throw std::runtime_error{"Failed to load ELF file for current process."};
                }
                auto kernels =
                        find_section_if(reader, [](const ELFIO::section* x) { return x->get_name() == kernel_section; });
                if (kernels) { 
                    ks.emplace_back(kernels->get_data(), kernels->get_data() + kernels->get_size());
                }

                dl_iterate_phdr(copy_kernel_sections_<>, &ks);
                for (auto&& x : ks) {
                    size_t offset = 0;
                    while(offset < x.size()) {
                        size_t read_bundle_size = 0;
                        Bundled_code_header tmp{x.cbegin()+offset,
                                                x.cend(), 
                                                &read_bundle_size};
                        if (valid(tmp)) {
                            r.push_back(std::move(tmp));
                            offset+=read_bundle_size;
                        }
                        else {
                            break;
                        }
                    }
                }
            });

            return r;
        }

        static
        void make_code_object_table_(
            const Bundled_code_header& x, Code_object_table& y)
        {
            for (auto&& z : bundles(x)) {
                y[triple_to_hsa_isa(z.triple)].push_back(
                /*
                    make_code_object_reader(z.blob));
                */ z.blob);
            }
            y.erase(hsa_isa_t{0});
        }

        static
        const Code_object_table& code_object_table_()
        {
            static Code_object_table r;

            static std::once_flag f;
            std::call_once(f, []() {
                for (auto&& x : kernel_sections_()) {
                    make_code_object_table_(x, r);
                }
            });

            return r;
        }

        void make_executable_table_(
            const Code_object_table& x, Executable_table& y) const
        {
            for (auto&& a : acc_) {
                const auto it = x.find(hsa_agent_isa(a));
                if (it != x.cend()) {
                    for (auto&& z : it->second) {
                        y[hsa_agent(a)].push_back(executable(z, hsa_agent(a)));
                    }
                }
            }
        }

        const Executable_table& executable_table_() const
        {
            static Executable_table r;

            static std::once_flag f;
            std::call_once(f, [this]() {
               make_executable_table_(code_object_table_(), r);
            });
            return r;
        }

        static
        decltype(HSA_STATUS_SUCCESS) copy_kernel_symbols(
            hsa_executable_t, hsa_agent_t x, hsa_executable_symbol_t y, void* z)
        {
            auto p = static_cast<typename Kernel_table::mapped_type*>(z);

            if (is_kernel(y)) p->push_back(y);

            return HSA_STATUS_SUCCESS;
        }

        void make_kernel_table_(
            const Executable_table& x, Kernel_table& y) const
        {
            for (auto&& e : x) {
                for (auto&& ex : e.second) {
                    hsa_executable_iterate_agent_symbols(
                        handle(ex), e.first, copy_kernel_symbols, &y[e.first]);
                }
            }
        }

        const Kernel_table& kernel_table_() const
        {
            static Kernel_table r;

            static std::once_flag f;
            std::call_once(f, [this]() {
                make_kernel_table_(executable_table_(), r);
            });

            return r;
        }

        Program_state() : acc_{hc::accelerator::get_all()}
        {
            acc_.erase(
                std::remove_if(
                    acc_.begin(),
                    acc_.end(),
                    [](const hc::accelerator& x) { return !x.is_hsa_accelerator(); }),
                acc_.end());
        }
    public:
        Program_state(const Program_state&) = default;
        Program_state(Program_state&&) = default;

        Program_state& operator=(const Program_state&) = default;
        Program_state& operator=(Program_state&&) = default;

        ~Program_state() = default;
    };

    inline
    const Program_state& program_state()
    {
        static const Program_state r;

        return r;
    }
}
