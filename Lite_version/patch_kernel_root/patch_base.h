#pragma once
#include <iostream>
#include <vector>
#include "patch_kernel_root.h"
#include "3rdparty/aarch64_asm_helper.h"
#include "analyze/symbol_analyze.h"

class PatchBase {
public:
	PatchBase(const std::vector<char>& file_buf, size_t cred_uid_offset);
	PatchBase(const PatchBase& other);
	~PatchBase();
	size_t patch_jump(size_t patch_addr, size_t jump_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
protected:
	int get_cred_atomic_usage_len();
	int get_cred_uid_region_len();
	int get_cred_euid_offset();
	int get_cred_securebits_padding();
	uint64_t get_cap_ability_max();
	int get_cap_cnt();

	bool is_CONFIG_THREAD_INFO_IN_TASK();
	void get_current_to_reg(std::shared_ptr<asmjit::a64::Assembler> a, asmjit::a64::GpX x);
	std::vector<size_t> find_all_aarch64_ret_offsets(size_t offset, size_t size);

	const std::vector<char>& m_file_buf;
	KernelVersionParser m_kernel_ver_parser;
	size_t m_cred_uid_offset = 0;
};