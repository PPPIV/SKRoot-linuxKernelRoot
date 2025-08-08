#include "patch_avc_denied.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchAvcDenied::PatchAvcDenied(const std::vector<char>& file_buf, const SymbolRegion& avc_denied)
	: PatchBase(file_buf), m_avc_denied(avc_denied) {}

PatchAvcDenied::~PatchAvcDenied() {}

int PatchAvcDenied::get_need_read_cap_cnt() {
	int cnt = get_cap_cnt();
	if (cnt < 5) {
		cnt = 3;
	}
	return cnt;
}

size_t PatchAvcDenied::patch_avc_denied_first_guide(const SymbolRegion& hook_func_start_region, const std::vector<size_t>& task_struct_offset_cred,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;
	size_t avc_denied_addr = m_avc_denied.offset + m_avc_denied.size - 4;

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);

	a->mrs(x11, sp_el0_id);
	for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
		if (x != task_struct_offset_cred.size() - 1) {
			a->ldr(x11, ptr(x11, task_struct_offset_cred[x]));
		}
	}
	a->ldr(x11, ptr(x11, task_struct_offset_cred.back()));

	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(asm_info);
	if (bytes.size() == 0) {
		return 0;
	}
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_avc_denied failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	patch_jump(avc_denied_addr, hook_func_start_addr, vec_out_patch_bytes_data);
	return shellcode_size;
}

size_t PatchAvcDenied::patch_avc_denied_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	int atomic_usage_len = get_cred_atomic_usage_len();
	int cred_euid_start_pos = get_cred_euid_offset();
	int uid_region_len = get_cred_uid_region_len();
	int securebits_padding = get_cred_securebits_padding();
	uint64_t cap_ability_max = get_cap_ability_max();
	int cap_cnt = get_need_read_cap_cnt();

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	Label label_end = a->newLabel();
	Label label_cycle_cap = a->newLabel();

	a->ldr(w12, ptr(x11, cred_euid_start_pos));
	a->cbnz(w12, label_end);
	a->add(x11, x11, Imm(atomic_usage_len + uid_region_len));
	a->mov(w12, Imm(0xc));
	a->ldr(w13, ptr(x11).post(4 + securebits_padding));
	a->cmp(w12, w13);
	a->b(CondCode::kNE, label_end);
	a->mov(x12, Imm(cap_ability_max));
	a->mov(x13, Imm(cap_cnt));
	a->bind(label_cycle_cap);
	a->ldr(x14, ptr(x11).post(8));
	a->cmp(x14, x12);
	a->b(CondCode::kCC, label_end);
	a->subs(x13, x13, Imm(1));
	a->b(CondCode::kNE, label_cycle_cap);

	a->mov(w0, wzr);
	a->bind(label_end);
	a->ret(x30);
	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::vector<uint8_t> bytes = aarch64_asm_to_bytes(asm_info);
	if (bytes.size() == 0) {
		return 0;
	}
	std::string str_bytes = bytes2hex((const unsigned char*)bytes.data(), bytes.size());
	size_t shellcode_size = str_bytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_avc_denied failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	return shellcode_size;
}
