#pragma once
#include "patch_do_execve.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;

PatchDoExecve::PatchDoExecve(const std::vector<char>& file_buf, const KernelSymbolOffset& sym) : PatchBase(file_buf) {
	init_do_execve_param(sym);
}
PatchDoExecve::~PatchDoExecve() {}

void PatchDoExecve::init_do_execve_param(const KernelSymbolOffset& sym) {
	if (m_kernel_ver_parser.is_kernel_version_less("3.14.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execve_common;
		m_doexecve_reg_param.do_execve_key_reg = 0;
		m_doexecve_reg_param.is_single_filename = true;
	}
	if (m_kernel_ver_parser.is_kernel_version_less("3.19.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execve_common;
		m_doexecve_reg_param.do_execve_key_reg = 0;
	}
	else  if (m_kernel_ver_parser.is_kernel_version_less("4.18.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execveat_common;
		m_doexecve_reg_param.do_execve_key_reg = 1;
	}
	else if (m_kernel_ver_parser.is_kernel_version_less("5.9.0")) {
		m_doexecve_reg_param.do_execve_addr = sym.__do_execve_file;
		m_doexecve_reg_param.do_execve_key_reg = 1;
	} else {
		// default linux kernel useage
		m_doexecve_reg_param.do_execve_addr = sym.do_execveat_common;
		m_doexecve_reg_param.do_execve_key_reg = 1;
	}

	if (m_doexecve_reg_param.do_execve_addr == 0) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execve;
		m_doexecve_reg_param.do_execve_key_reg = 0;
	}
	if (m_doexecve_reg_param.do_execve_addr == 0) {
		m_doexecve_reg_param.do_execve_addr = sym.do_execveat;
		m_doexecve_reg_param.do_execve_key_reg = 1;
	}
}

int PatchDoExecve::get_need_write_cap_cnt() {
	return get_cap_cnt();
}

bool PatchDoExecve::is_thread_info_in_stack_bottom() {
	if (m_kernel_ver_parser.is_kernel_version_less("4.9.0")) {
		return true;
	}
	return false;
}

size_t PatchDoExecve::patch_do_execve(const SymbolRegion& hook_func_start_region, const std::vector<size_t>& task_struct_offset_cred, const std::vector<size_t>& task_struct_offset_seccomp,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {

	size_t hook_func_start_addr = hook_func_start_region.offset;
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	int atomic_usage_len = get_cred_atomic_usage_len();
	int securebits_padding = get_cred_securebits_padding();
	uint64_t cap_ability_max = get_cap_ability_max();
	int cap_cnt = get_need_write_cap_cnt();
	bool is_thread_info_in_stack = is_thread_info_in_stack_bottom();

	size_t do_execve_entry_hook_jump_back_addr = m_doexecve_reg_param.do_execve_addr + 4;
	char empty_root_key_buf[ROOT_KEY_LEN] = { 0 };

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	uint32_t sp_el0_id = SysReg::encode(3, 0, 4, 1, 0);
	Label label_end = a->newLabel();
	Label label_cycle_name = a->newLabel();
	a->embed((const uint8_t*)empty_root_key_buf, sizeof(empty_root_key_buf));
	a->mov(x0, x0);
	a->mov(x11, Imm(0xFFFFFFFFFFFFF001));
	a->cmp(a64::x(m_doexecve_reg_param.do_execve_key_reg), x11);
	a->b(CondCode::kCS, label_end);
	if (m_doexecve_reg_param.is_single_filename) {
		a->mov(x11, a64::x(m_doexecve_reg_param.do_execve_key_reg));
	} else {
		a->ldr(x11, ptr(a64::x(m_doexecve_reg_param.do_execve_key_reg)));
	}
	int32_t key_offset = -a->offset();
	aarch64_asm_adr_x(a, x12, key_offset);
	a->mov(x13, Imm(0));
	a->bind(label_cycle_name);
	a->ldrb(w14, ptr(x11, x13));
	a->ldrb(w15, ptr(x12, x13));
	a->cmp(w14, w15);
	a->b(CondCode::kNE, label_end);

	a->add(x13, x13, Imm(1));
	a->cmp(x13, Imm(ROOT_KEY_LEN));
	a->b(CondCode::kLT, label_cycle_name);
	a->mrs(x12, sp_el0_id);
	a->mov(x14, x12);
	for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
		if (x != task_struct_offset_cred.size() - 1) {
			a->ldr(x14, ptr(x14, task_struct_offset_cred[x]));
		}
	}

	a->ldr(x14, ptr(x14, task_struct_offset_cred.back()));
	a->add(x14, x14, Imm(atomic_usage_len));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->str(xzr, ptr(x14).post(8));
	a->mov(w13, Imm(0xc));
	a->str(w13, ptr(x14).post(4 + securebits_padding));
	a->mov(x13, Imm(cap_ability_max));
	a->stp(x13, x13, ptr(x14).post(16));
	a->stp(x13, x13, ptr(x14).post(16));
	if (cap_cnt == 5) {
		a->str(x13, ptr(x14).post(8));
	}
	if (is_thread_info_in_stack) {
		a->mov(x13, x12);
		a->and_(x13, x13, Imm((uint64_t)~(0x4000 - 1)));
		a->ldxr(w14, ptr(x13));
		a->bic(w14, w14, Imm(0xFFF));
		a->stxr(w15, w14, ptr(x13));
	} else {
		a->ldxr(w14, ptr(x12));
		a->bic(w14, w14, Imm(0xFFF));
		a->stxr(w15, w14, ptr(x12));
	}
	a->str(xzr, ptr(x12, task_struct_offset_seccomp.back()));
	a->bind(label_end);
	aarch64_asm_b(a, (int32_t)(do_execve_entry_hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(asm_info) << std::endl;

	auto [sp_bytes, data_size] = aarch64_asm_to_bytes(asm_info);
	if (!sp_bytes) {
		return 0;
	}
	std::string str_bytes = bytes2hex((const unsigned char*)sp_bytes.get(), data_size);
	size_t shellcode_size = str_bytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + m_doexecve_reg_param.do_execve_addr), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));
	str_bytes = str_bytes.substr(0, sizeof(empty_root_key_buf) * 2) + strHookOrigCmd + str_bytes.substr(sizeof(empty_root_key_buf) * 2 + 0x4 * 2);

	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_do_execve failed: not enough kernel space." << std::endl;
		return 0;
	}
	
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });

	patch_jump(m_doexecve_reg_param.do_execve_addr, hook_func_start_addr + sizeof(empty_root_key_buf), vec_out_patch_bytes_data);

	return shellcode_size;
}


size_t PatchDoExecve::patch_root_key(const std::string& root_key, size_t write_addr, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	if (write_addr == 0) { return 0; }
	std::cout << "Start writing addr: " << std::hex << write_addr << std::endl << std::endl;
	std::string str_root_key = root_key;
	if (str_root_key.length() > ROOT_KEY_LEN) {
		str_root_key = str_root_key.substr(0, ROOT_KEY_LEN);
	}
	std::string str_show_root_key_mem_byte = bytes2hex((const unsigned char*)str_root_key.c_str(), str_root_key.length());
	vec_out_patch_bytes_data.push_back({ str_show_root_key_mem_byte, write_addr });
	return str_root_key.length() / 2;
}