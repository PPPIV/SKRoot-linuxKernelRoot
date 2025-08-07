#pragma once
#include <iostream>
#include <vector>
#include "patch_kernel_root.h"
#include "analyze/symbol_analyze.h"
class PatchBase {
public:
	PatchBase(const std::vector<char>& file_buf);
	~PatchBase();
	size_t patch_jump(size_t patch_addr, size_t jump_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
protected:
	int get_cred_atomic_usage_len();
	int get_cred_uid_region_len();
	int get_cred_euid_start_pos();
	int get_cred_securebits_padding();
	uint64_t get_cap_ability_max();
	int get_cap_cnt();
	const std::vector<char>& m_file_buf;
	KernelVersionParser m_kernel_ver_parser;
};