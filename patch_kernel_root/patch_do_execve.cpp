#pragma once
#include "patch_do_execve.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchDoExecve::PatchDoExecve(const std::vector<char>& file_buf, const KernelSymbolOffset& sym,
	const SymbolAnalyze& symbol_analyze) : PatchBase(file_buf, sym, symbol_analyze) {

}
PatchDoExecve::~PatchDoExecve() {}

ExecveParam PatchDoExecve::get_do_execve_param() {
	ExecveParam param = { 0 };
	if (m_symbol_analyze.is_kernel_version_less("3.14.0")) {
		param.do_execve_addr = m_sym.do_execve_common;
		param.do_execve_key_reg = 0;
		param.is_single_filename = true;
	}
	if (m_symbol_analyze.is_kernel_version_less("3.19.0")) {
		param.do_execve_addr = m_sym.do_execve_common;
		param.do_execve_key_reg = 0;
	}
	else  if (m_symbol_analyze.is_kernel_version_less("4.18.0")) {
		param.do_execve_addr = m_sym.do_execveat_common;
		param.do_execve_key_reg = 1;
	}
	else if (m_symbol_analyze.is_kernel_version_less("5.9.0")) {
		param.do_execve_addr = m_sym.__do_execve_file;
		param.do_execve_key_reg = 1;
	}
	else {
		// default linux kernel useage
		param.do_execve_addr = m_sym.do_execveat_common;
		param.do_execve_key_reg = 1;
	}

	if (param.do_execve_addr == 0) {
		param.do_execve_addr = m_sym.do_execve;
		param.do_execve_key_reg = 0;
	}
	if (param.do_execve_addr == 0) {
		param.do_execve_addr = m_sym.do_execveat;
		param.do_execve_key_reg = 1;
	}
	return param;
}


int PatchDoExecve::get_need_write_cap_cnt() {
	return get_cap_cnt();
}

bool PatchDoExecve::is_thread_info_in_stack_bottom() {
	if (m_symbol_analyze.is_kernel_version_less("4.9.0")) {
		return true;
	}
	return false;
}

size_t PatchDoExecve::patch_do_execve(const std::string& str_root_key, const SymbolRegion& hook_func_start_region,
	const std::vector<size_t>& task_struct_offset_cred,
	const std::vector<size_t>& task_struct_offset_seccomp,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {

	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	const ExecveParam reg_param = get_do_execve_param();
	int atomic_usage_len = get_cred_atomic_usage_len();
	int securebits_padding = get_cred_securebits_padding();
	uint64_t cap_ability_max = get_cap_ability_max();
	int cap_cnt = get_need_write_cap_cnt();
	bool is_thread_info_in_stack = is_thread_info_in_stack_bottom();

	size_t do_execve_entry_hook_jump_back_addr = reg_param.do_execve_addr + 4;

	std::string str_show_root_key_mem_byte = bytes2hex((const unsigned char*)str_root_key.c_str(), str_root_key.length());

	vec_out_patch_bytes_data.push_back({ str_show_root_key_mem_byte, hook_func_start_addr });

	size_t shellcode_size = str_root_key.length();
	hook_func_start_addr += str_root_key.length();

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);
	Label label_end = a->newLabel();
	Label label_cycle_name = a->newLabel();
	a->mov(x0, x0);
	a->stp(x7, x8, ptr(sp).pre(-16));
	a->stp(x9, x10, ptr(sp).pre(-16));
	a->stp(x11, x12, ptr(sp).pre(-16));
	a->mov(x7, Imm(0xFFFFFFFFFFFFF001));
	a->cmp(a64::x(reg_param.do_execve_key_reg), x7);
	a->b(CondCode::kCS, label_end);
	if (reg_param.is_single_filename) {
		a->mov(x7, a64::x(reg_param.do_execve_key_reg));
	} else {
		a->ldr(x7, ptr(a64::x(reg_param.do_execve_key_reg)));
	}
	int32_t key_offset = (hook_func_start_addr - 48) - (hook_func_start_addr + a->offset());
	aarch64_asm_adr_x(a, x8, key_offset);
	a->mov(x9, Imm(0));
	a->bind(label_cycle_name);
	a->ldrb(w10, ptr(x7, x9));
	a->ldrb(w11, ptr(x8, x9));
	a->cmp(w10, w11);
	a->b(CondCode::kNE, label_end);
	a->add(x9, x9, Imm(1));
	a->cmp(x9, Imm(str_root_key.length()));
	a->b(CondCode::kLT, label_cycle_name);
	a->mrs(x8, sp_el0_id);
	a->mov(x10, x8);
	for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
		if (x != task_struct_offset_cred.size() - 1) {
			a->ldr(x10, ptr(x10, task_struct_offset_cred[x]));
		}
	}
	a->ldr(x10, ptr(x10, task_struct_offset_cred.back()));
	a->add(x10, x10, Imm(atomic_usage_len));
	a->str(xzr, ptr(x10).post(8));
	a->str(xzr, ptr(x10).post(8));
	a->str(xzr, ptr(x10).post(8));
	a->str(xzr, ptr(x10).post(8));
	a->mov(w9, Imm(0xc));
	a->str(w9, ptr(x10).post(4 + securebits_padding));
	a->mov(x9, Imm(cap_ability_max));
	a->stp(x9, x9, ptr(x10).post(16));
	a->stp(x9, x9, ptr(x10).post(16));
	if (cap_cnt == 5) {
		a->str(x9, ptr(x10).post(8));
	}
	if (is_thread_info_in_stack) {
		a->mov(x9, x8);
		a->and_(x9, x9, Imm((uint64_t)~(0x4000 - 1)));
		a->ldxr(w10, ptr(x9));
		a->bic(w10, w10, Imm(0xFFF));
		a->stxr(w11, w10, ptr(x9));
	} else {
		a->ldxr(w10, ptr(x8));
		a->bic(w10, w10, Imm(0xFFF));
		a->stxr(w11, w10, ptr(x8));
	}
	a->str(xzr, ptr(x8, task_struct_offset_seccomp.back()));
	a->bind(label_end);
	a->ldp(x11, x12, ptr(sp).post(16));
	a->ldp(x9, x10, ptr(sp).post(16));
	a->ldp(x7, x8, ptr(sp).post(16));
	aarch64_asm_b(a, (int32_t)(do_execve_entry_hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(asm_info) << std::endl;

	std::string strBytes = aarch64_asm_to_bytes(asm_info);
	if (!strBytes.length()) {
		return 0;
	}
	shellcode_size += strBytes.length() / 2;
	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + reg_param.do_execve_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	strBytes = strHookOrigCmd + strBytes.substr(0x4 * 2);

	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_do_execve failed: not enough kernel space." << std::endl;
		return 0;
	}
	
	vec_out_patch_bytes_data.push_back({ strBytes, hook_func_start_addr });

	patch_jump(reg_param.do_execve_addr, hook_func_start_addr, vec_out_patch_bytes_data);

	return shellcode_size;
}