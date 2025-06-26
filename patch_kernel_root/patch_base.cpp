#include "patch_base.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchBase::PatchBase(const std::vector<char>& file_buf) : m_file_buf(file_buf), m_kernel_ver_parser(file_buf) {}

PatchBase::~PatchBase() {}

int PatchBase::get_cred_atomic_usage_len() {
	int len = 8;
	if (m_kernel_ver_parser.is_kernel_version_less("6.6.0")) {
		len = 4;
	}
	return len;
}

int PatchBase::get_cred_securebits_padding() {
	if (get_cred_atomic_usage_len() == 8) {
		return 4;
	}
	return 0;
}

uint64_t PatchBase::get_cap_ability_max() {
	uint64_t cap = 0x3FFFFFFFFF;
	if (m_kernel_ver_parser.is_kernel_version_less("5.8.0")) {
		cap = 0x3FFFFFFFFF;
	}
	else if (m_kernel_ver_parser.is_kernel_version_less("5.9.0")) {
		cap = 0xFFFFFFFFFF;
	}
	else {
		cap = 0x1FFFFFFFFFF;
	}
	return cap;
}

int PatchBase::get_cap_cnt() {
	int cnt = 0;
	if (m_kernel_ver_parser.is_kernel_version_less("4.3.0")) {
		cnt = 4;
	} else {
		cnt = 5;
	}
	return cnt;
}

size_t PatchBase::patch_jump(size_t patch_addr, size_t jump_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	aarch64_asm_info asm_info = init_aarch64_asm();
	aarch64_asm_b(asm_info.a, (int32_t)(jump_addr - patch_addr));
	auto [sp_bytes, data_size] = aarch64_asm_to_bytes(asm_info);
	if (!sp_bytes) {
		return 0;
	}
	std::string str_bytes = bytes2hex((const unsigned char*)sp_bytes.get(), data_size);
	vec_out_patch_bytes_data.push_back({ str_bytes, patch_addr });
	return str_bytes.length() / 2;
}