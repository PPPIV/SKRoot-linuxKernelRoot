#include "patch_avc_denied.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchAvcDenied::PatchAvcDenied(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
	const SymbolAnalyze& symbol_analyze) : PatchBase(file_buf, sym, symbol_analyze) {

}

PatchAvcDenied::~PatchAvcDenied()
{
}

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
	size_t avc_denied_addr = m_sym.avc_denied.offset + m_sym.avc_denied.size - 4;

	
	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);

	a->stp(x7, x8, ptr(sp).pre(-16));
	a->stp(x9, x10, ptr(sp).pre(-16));

	
	a->mrs(x7, sp_el0_id);
	for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
		if (x != task_struct_offset_cred.size() - 1) {
			a->ldr(x7, ptr(x7, task_struct_offset_cred[x]));
		}
	}
	a->ldr(x7, ptr(x7, task_struct_offset_cred.back()));

	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::string strBytes = aarch64_asm_to_bytes(asm_info);
	if (!strBytes.length()) {
		return 0;
	}
	size_t shellcode_size = strBytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_avc_denied failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	patch_jump(avc_denied_addr, hook_func_start_addr, vec_out_patch_bytes_data);
	return shellcode_size;
}

size_t PatchAvcDenied::patch_avc_denied_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;
	int atomic_usage_len = get_cred_atomic_usage_len();
	int securebits_padding = get_cred_securebits_padding();
	uint64_t cap_ability_max = get_cap_ability_max();
	int cap_cnt = get_need_read_cap_cnt();

	
	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	Label label_end = a->newLabel();
	Label label_cycle_uid = a->newLabel();
	Label label_cycle_cap = a->newLabel();
	a->add(x7, x7, Imm(atomic_usage_len)); 
	a->mov(x8, Imm(8));
	a->bind(label_cycle_uid);
	a->ldr(w9, ptr(x7).post(4));
	a->cbnz(w9, label_end);
	a->subs(x8, x8, Imm(1));
	a->b(CondCode::kNE, label_cycle_uid);
	a->mov(w8, Imm(0xc));
	a->ldr(w9, ptr(x7).post(4 + securebits_padding));
	a->cmp(w8, w9);
	a->b(CondCode::kNE, label_end);
	a->mov(x8, Imm(cap_ability_max));
	a->mov(x9, Imm(cap_cnt));
	a->bind(label_cycle_cap);
	a->ldr(x10, ptr(x7).post(8));
	a->cmp(x10, x8);
	a->b(CondCode::kCC, label_end);
	a->subs(x9, x9, Imm(1));
	a->b(CondCode::kNE, label_cycle_cap);
	a->mov(w0, wzr);
	a->bind(label_end);

	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::string strBytes = aarch64_asm_to_bytes(asm_info);
	if (!strBytes.length()) {
		return 0;
	}
	size_t shellcode_size = strBytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_avc_denied failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	return shellcode_size;
}

size_t PatchAvcDenied::patch_avc_denied_end_guide(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	a->ldp(x9, x10, ptr(sp).post(16));
	a->ldp(x7, x8, ptr(sp).post(16));
	a->ret(x30);
	std::cout << print_aarch64_asm(asm_info) << std::endl;
	std::string strBytes = aarch64_asm_to_bytes(asm_info);
	if (!strBytes.length()) {
		return 0;
	}
	size_t shellcode_size = strBytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_avc_denied failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	return shellcode_size;
}
