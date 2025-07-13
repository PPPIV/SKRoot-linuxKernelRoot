#include "symbol_analyze.h"

SymbolAnalyze::SymbolAnalyze(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_sym_parser(file_buf)
{
}

SymbolAnalyze::~SymbolAnalyze()
{
}

bool SymbolAnalyze::analyze_kernel_symbol() {
	if (!m_kernel_sym_parser.init_kallsyms_lookup_name()) {
		std::cout << "Failed to initialize kallsyms lookup name" << std::endl;
		return false;
	}
	if (!find_symbol_offset()) {
		std::cout << "Failed to find symbol offset" << std::endl;
		return false;
	}
	return true;
}

KernelSymbolOffset SymbolAnalyze::get_symbol_offset() {
	return m_kernel_sym_offset;
}

bool SymbolAnalyze::find_symbol_offset() {
	m_kernel_sym_offset._text = kallsyms_matching_single("_text");
	m_kernel_sym_offset._stext = kallsyms_matching_single("_stext");

	m_kernel_sym_offset.die = parse_symbol_region(kallsyms_matching_single("die"));
	m_kernel_sym_offset.arm64_notify_die = parse_symbol_region(kallsyms_matching_single("arm64_notify_die"));
	m_kernel_sym_offset.kernel_halt = parse_symbol_region(kallsyms_matching_single("kernel_halt"));
	m_kernel_sym_offset.drm_dev_printk = parse_symbol_region(kallsyms_matching_single("drm_dev_printk"));
	m_kernel_sym_offset.dev_printk = parse_symbol_region(kallsyms_matching_single("__dev_printk"));

	m_kernel_sym_offset.__do_execve_file = kallsyms_matching_single("__do_execve_file");
	m_kernel_sym_offset.do_execveat_common = kallsyms_matching_single("do_execveat_common");
	if (m_kernel_sym_offset.do_execveat_common == 0) {
		m_kernel_sym_offset.do_execveat_common = kallsyms_matching_single("do_execveat_common", true);
	}

	m_kernel_sym_offset.do_execve_common = kallsyms_matching_single("do_execve_common");
	if (m_kernel_sym_offset.do_execve_common == 0) {
		m_kernel_sym_offset.do_execve_common = kallsyms_matching_single("do_execve_common", true);
	}

	m_kernel_sym_offset.do_execveat = kallsyms_matching_single("do_execveat");
	m_kernel_sym_offset.do_execve = kallsyms_matching_single("do_execve");

	m_kernel_sym_offset.avc_denied = parse_symbol_region(kallsyms_matching_single("avc_denied"));
	if (m_kernel_sym_offset.avc_denied.offset == 0) {
		m_kernel_sym_offset.avc_denied = parse_symbol_region(kallsyms_matching_single("avc_denied", true));
	}
	m_kernel_sym_offset.filldir64 = kallsyms_matching_single("filldir64");
	m_kernel_sym_offset.freeze_task = kallsyms_matching_single("freeze_task");

	m_kernel_sym_offset.revert_creds = kallsyms_matching_single("revert_creds");
	m_kernel_sym_offset.prctl_get_seccomp = kallsyms_matching_single("prctl_get_seccomp"); // backup: seccomp_filter_release
	 
	
	m_kernel_sym_offset.__cfi_check = parse_symbol_region(kallsyms_matching_single("__cfi_check"));
	m_kernel_sym_offset.__cfi_check_fail = kallsyms_matching_single("__cfi_check_fail");
	m_kernel_sym_offset.__cfi_slowpath_diag = kallsyms_matching_single("__cfi_slowpath_diag");
	m_kernel_sym_offset.__cfi_slowpath = kallsyms_matching_single("__cfi_slowpath");
	m_kernel_sym_offset.__ubsan_handle_cfi_check_fail_abort = kallsyms_matching_single("__ubsan_handle_cfi_check_fail_abort");
	m_kernel_sym_offset.__ubsan_handle_cfi_check_fail = kallsyms_matching_single("__ubsan_handle_cfi_check_fail");
	m_kernel_sym_offset.report_cfi_failure = kallsyms_matching_single("report_cfi_failure");
	return (m_kernel_sym_offset.do_execve || m_kernel_sym_offset.do_execveat || m_kernel_sym_offset.do_execveat_common) 
		&& m_kernel_sym_offset.avc_denied.offset
		&& m_kernel_sym_offset.filldir64
		&& m_kernel_sym_offset.freeze_task
		&& m_kernel_sym_offset.revert_creds
		&& m_kernel_sym_offset.prctl_get_seccomp;
}


uint64_t SymbolAnalyze::kallsyms_matching_single(const char* name, bool fuzzy) {
	if (fuzzy) {
		auto map = kallsyms_matching_all(name);
		if (map.size()) {
			return map.begin()->second;
		}
		return 0;
	}
	return m_kernel_sym_parser.kallsyms_lookup_name(name);
}

std::unordered_map<std::string, uint64_t> SymbolAnalyze::kallsyms_matching_all(const char* name) {
	return m_kernel_sym_parser.kallsyms_lookup_names_like(name);
}

SymbolRegion SymbolAnalyze::parse_symbol_region(uint64_t offset) {
	if (offset == 0) { return {}; }
	constexpr uint32_t kRetInstr = 0xD65F03C0;
	const size_t buf_size = m_file_buf.size();
	SymbolRegion results;
	results.offset = offset;
	for (size_t i = offset; i + 4 <= buf_size; i += 4) {
		uint32_t instr = *reinterpret_cast<const uint32_t*>(&m_file_buf[i]);
		if (instr == kRetInstr) {
			results.size = i - offset + 4;
			break;
		}
	}
	if (results.size == 0) {
		results.size = 4;
	}
	return results;
}

std::unordered_map<std::string, SymbolRegion> SymbolAnalyze::parse_symbols_region(const std::unordered_map<std::string, uint64_t>& symbols) {
	std::unordered_map<std::string, SymbolRegion> results;
	for (const auto& [func_name, offset] : symbols) {
		if (func_name.find(".cfi_jt") != std::string::npos) { continue; }
		results.emplace(func_name, parse_symbol_region(offset));
	}
	return results;
}