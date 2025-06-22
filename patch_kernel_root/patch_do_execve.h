#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"

struct ExecveParam {
	size_t do_execve_addr = 0;
	size_t do_execve_key_reg = 0;
	bool is_single_filename = false;
};

class PatchDoExecve : public PatchBase
{
public:
	PatchDoExecve(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
		const SymbolAnalyze& symbol_analyze);
	~PatchDoExecve();

	size_t patch_do_execve(const std::string& str_root_key, const SymbolRegion& hook_func_start_region,
		const std::vector<size_t>& task_struct_offset_cred,
		const std::vector<size_t>& task_struct_offset_seccomp,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	ExecveParam get_do_execve_param();
	int get_need_write_cap_cnt();
	bool is_thread_info_in_stack_bottom();
};