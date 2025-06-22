#include "patch_filldir64.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;
PatchFilldir64::PatchFilldir64(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
	const SymbolAnalyze& symbol_analyze) : PatchBase(file_buf, sym, symbol_analyze) {

}

PatchFilldir64::~PatchFilldir64()
{
}


size_t PatchFilldir64::patch_filldir64_root_key_guide(size_t root_key_mem_addr, const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;
	size_t filldir64_addr = m_sym.filldir64;

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;

	a->stp(x7, x8, ptr(sp).pre(-16));
	a->stp(x9, x10, ptr(sp).pre(-16));
	int root_key_adr_offset = root_key_mem_addr - (hook_func_start_addr + a->offset());
	aarch64_asm_adr_x(a, x7, root_key_adr_offset);

	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::string strBytes = aarch64_asm_to_bytes(asm_info);
	if (!strBytes.length()) {
		return 0;
	}
	size_t shellcode_size = strBytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_filldir64 failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });

	patch_jump(filldir64_addr, hook_func_start_addr, vec_out_patch_bytes_data);

	return shellcode_size;
}

size_t PatchFilldir64::patch_filldir64_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	
	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	Label label_end = a->newLabel();
	Label label_cycle_name = a->newLabel();
	a->cmp(w2, Imm(16));
	a->b(CondCode::kNE, label_end);
	a->mov(x8, Imm(0));
	a->bind(label_cycle_name);
	a->ldrb(w9, ptr(x1, x8));
	a->ldrb(w10, ptr(x7, x8));
	a->cmp(w9, w10);
	a->b(CondCode::kNE, label_end);
	a->add(x8, x8, Imm(1));
	a->cmp(x8, Imm(16));
	a->b(CondCode::kLT, label_cycle_name);
	a->ldp(x9, x10, ptr(sp).post(16));
	a->ldp(x7, x8, ptr(sp).post(16));
	a->mov(x0, xzr);
	a->ret(x30);
	a->bind(label_end);
	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::string strBytes = aarch64_asm_to_bytes(asm_info);
	if (!strBytes.length()) {
		return 0;
	}
	size_t shellcode_size = strBytes.length() / 2;
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_filldir64 failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	return shellcode_size;

}

size_t PatchFilldir64::patch_filldir64_end_guide(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;
	size_t filldir64_addr = m_sym.filldir64;
	size_t filldir64_entry_hook_jump_back_addr = m_sym.filldir64 + 4;

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	a->ldp(x9, x10, ptr(sp).post(16));
	a->ldp(x7, x8, ptr(sp).post(16));
	a->mov(x0, x0);
	aarch64_asm_b(a, (int32_t)(filldir64_entry_hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::string strBytes = aarch64_asm_to_bytes(asm_info);
	if (!strBytes.length()) {
		return 0;
	}
	size_t shellcode_size = strBytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + filldir64_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));

	int end_order_len = a->offset() - 2 * 4;
	strBytes = strBytes.substr(0, (end_order_len) * 2) + strHookOrigCmd + strBytes.substr((end_order_len + 4) * 2);
	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_filldir64 failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });
	return shellcode_size;
}