#include "patch_base.h"
#include "analyze/base_func.h"

using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

struct cred_uid_info {
	uint32_t uid; /* real UID of the task */
	uint32_t gid; /* real GID of the task */
	uint32_t suid; /* saved UID of the task */
	uint32_t sgid; /* saved GID of the task */
	uint32_t euid; /* effective UID of the task */
	uint32_t egid; /* effective GID of the task */
	uint32_t fsuid; /* UID for VFS ops */
	uint32_t fsgid; /* GID for VFS ops */
};

PatchBase::PatchBase(const std::vector<char>& file_buf, size_t cred_uid_offset) : 
	m_file_buf(file_buf), m_kernel_ver_parser(file_buf), m_cred_uid_offset(cred_uid_offset) {}

PatchBase::PatchBase(const PatchBase& other)
	: m_file_buf(other.m_file_buf)
	, m_kernel_ver_parser(other.m_file_buf)
	, m_cred_uid_offset(other.m_cred_uid_offset)
{}

PatchBase::~PatchBase() {}

int PatchBase::get_cred_atomic_usage_len() {
	return m_cred_uid_offset;
}

int PatchBase::get_cred_uid_region_len() {
	return sizeof(cred_uid_info);
}

int PatchBase::get_cred_euid_offset() {
	return get_cred_atomic_usage_len() + offsetof(cred_uid_info, euid);
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
	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(asm_info);
	if (bytes.size() == 0) {
		return 0;
	}
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	vec_out_patch_bytes_data.push_back({ str_bytes, patch_addr });
	return bytes.size();
}

bool PatchBase::is_CONFIG_THREAD_INFO_IN_TASK() {
	return !m_kernel_ver_parser.is_kernel_version_less("4.4.207");
}

void PatchBase::get_current_to_reg(std::shared_ptr<asmjit::a64::Assembler> a, asmjit::a64::GpX x) {
	struct thread_info {
		uint64_t flags;		/* low level flags */
		uint64_t addr_limit;	/* address limit */
	};
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);
	a->mrs(x, sp_el0_id);
	if (!is_CONFIG_THREAD_INFO_IN_TASK()) {
		a->and_(x, x, Imm((uint64_t)~(0x4000 - 1)));
		a->ldr(x, ptr(x, sizeof(thread_info)));
	}
}