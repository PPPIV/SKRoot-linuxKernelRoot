#pragma once
#include "kernel_symbol_parser.h"
#include <sstream>
#include <algorithm>
#include <unordered_map>

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

KernelSymbolParser::KernelSymbolParser(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_ver_parser(file_buf)
	, m_kallsyms_lookup_name_6_6_30(file_buf)
	, m_kallsyms_lookup_name_6_1_60(file_buf)
	, m_kallsyms_lookup_name_6_1_42(file_buf)
	, m_kallsyms_lookup_name_4_6_0(file_buf)
	, m_kallsyms_lookup_name(file_buf)
{
}

KernelSymbolParser::~KernelSymbolParser()
{
}

bool KernelSymbolParser::init_kallsyms_lookup_name() {

	std::string current_version = m_kernel_ver_parser.get_kernel_version();
	if (current_version.empty()) {
		std::cout << "Failed to read Linux kernel version" << std::endl;
		return false;
	}
	std::cout << "Find the current Linux kernel version: " << current_version << std::endl;
	std::cout << std::endl;

	if (m_kernel_ver_parser.is_kernel_version_less("4.6.0")) {
		if (!m_kallsyms_lookup_name.init()) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("6.1.42")) {
		if (!m_kallsyms_lookup_name_4_6_0.init()) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("6.1.60")) {
		if (!m_kallsyms_lookup_name_6_1_42.init()) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else if (m_kernel_ver_parser.is_kernel_version_less("6.6.30")) {
		if (!m_kallsyms_lookup_name_6_1_60.init()) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	} else {
		if (!m_kallsyms_lookup_name_6_6_30.init()) {
			std::cout << "Failed to analyze kernel kallsyms lookup name information" << std::endl;
			return false;
		}
	}
	return true;
}

uint64_t KernelSymbolParser::kallsyms_lookup_name(const char* name) {
	if (m_kallsyms_lookup_name_6_6_30.is_inited()) {
		return m_kallsyms_lookup_name_6_6_30.kallsyms_lookup_name(name);
	} else if (m_kallsyms_lookup_name_6_1_60.is_inited()) {
		return m_kallsyms_lookup_name_6_1_60.kallsyms_lookup_name(name);
	} else if (m_kallsyms_lookup_name_6_1_42.is_inited()) {
		return m_kallsyms_lookup_name_6_1_42.kallsyms_lookup_name(name);
	} else if (m_kallsyms_lookup_name_4_6_0.is_inited()) {
		return m_kallsyms_lookup_name_4_6_0.kallsyms_lookup_name(name);
	} else if (m_kallsyms_lookup_name.is_inited()) {
		return m_kallsyms_lookup_name.kallsyms_lookup_name(name);
	}
	return 0;
}

std::unordered_map<std::string, uint64_t> KernelSymbolParser::kallsyms_lookup_names_like(const char* name) {
    std::unordered_map<std::string, uint64_t> all_symbols;
    if (m_kallsyms_lookup_name_6_6_30.is_inited()) {
        all_symbols = m_kallsyms_lookup_name_6_6_30.kallsyms_on_each_symbol();
    } else if (m_kallsyms_lookup_name_6_1_60.is_inited()) {
        all_symbols = m_kallsyms_lookup_name_6_1_60.kallsyms_on_each_symbol();
    } else if (m_kallsyms_lookup_name_6_1_42.is_inited()) {
        all_symbols = m_kallsyms_lookup_name_6_1_42.kallsyms_on_each_symbol();
    } else if (m_kallsyms_lookup_name_4_6_0.is_inited()) {
        all_symbols = m_kallsyms_lookup_name_4_6_0.kallsyms_on_each_symbol();
    } else if (m_kallsyms_lookup_name.is_inited()) {
        all_symbols = m_kallsyms_lookup_name.kallsyms_on_each_symbol();
    }

    static const std::vector<std::string> skip_suffixes = {
        ".cfi_jt",
    };

    std::unordered_map<std::string, uint64_t> result;
    for (const auto& [sym_name, addr] : all_symbols) {
        if (sym_name.find(name) == std::string::npos) {
            continue;
		}
        bool skip = std::any_of(
            skip_suffixes.begin(), skip_suffixes.end(),
            [&](const std::string& suf) {
                return sym_name.size() >= suf.size()
                    && sym_name.compare(
                           sym_name.size() - suf.size(),
                           suf.size(), suf) == 0;
            });
        if (skip) {
            continue;
		}
        result[sym_name] = addr;
    }
    return result;
}