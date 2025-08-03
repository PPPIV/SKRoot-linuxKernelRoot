#include "patch_freeze_task.h"
#include "analyze/base_func.h"
#include "3rdparty/aarch64_asm_helper.h"
using namespace asmjit;
using namespace asmjit::a64;
using namespace asmjit::a64::Predicate;
PatchFreezeTask::PatchFreezeTask(const std::vector<char>& file_buf, size_t freeze_task) : PatchBase(file_buf), m_freeze_task(freeze_task) {}

PatchFreezeTask::~PatchFreezeTask() {}

size_t PatchFreezeTask::patch_freeze_task(const SymbolRegion& hook_func_start_region, const std::vector<size_t>& task_struct_offset_cred,
	std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	size_t hook_func_start_addr = hook_func_start_region.offset; 
	if (hook_func_start_addr == 0) { return 0; }
	std::cout << "Start hooking addr:  " << std::hex << hook_func_start_addr << std::endl << std::endl;

	int cred_euid_start_pos = get_cred_euid_start_pos();

	size_t hook_jump_back_addr = m_freeze_task + 4;

	aarch64_asm_info asm_info = init_aarch64_asm();
	auto& a = asm_info.a;
	Label label_end = a->newLabel();

	a->mov(x11, x0);
	for (auto x = 0; x < task_struct_offset_cred.size(); x++) {
		if (x != task_struct_offset_cred.size() - 1) {
			a->ldr(x11, ptr(x11, task_struct_offset_cred[x]));
		}
	}
	a->ldr(x11, ptr(x11, task_struct_offset_cred.back()));
	a->cbz(x11, label_end);
	a->ldr(w12, ptr(x11, cred_euid_start_pos));
	a->cbnz(w12, label_end);
	a->mov(w0, wzr);
	a->ret(x30);
	a->bind(label_end);
	a->mov(x0, x0);
	aarch64_asm_b(a, (int32_t)(hook_jump_back_addr - (hook_func_start_addr + a->offset())));
	std::cout << print_aarch64_asm(asm_info) << std::endl;

	auto [sp_bytes, data_size] = aarch64_asm_to_bytes(asm_info);
	if (!sp_bytes) {
		return 0;
	}
	std::string str_bytes = bytes2hex((const unsigned char*)sp_bytes.get(), data_size);
	size_t shellcode_size = str_bytes.length() / 2;

	char hookOrigCmd[4] = { 0 };
	memcpy(&hookOrigCmd, (void*)((size_t)&m_file_buf[0] + m_freeze_task), sizeof(hookOrigCmd));
	std::string strHookOrigCmd = bytes2hex((const unsigned char*)hookOrigCmd, sizeof(hookOrigCmd));

	int end_order_len = a->offset() - 2 * 4;
	str_bytes = str_bytes.substr(0, (end_order_len) * 2) + strHookOrigCmd + str_bytes.substr((end_order_len + 4) * 2);

	if (shellcode_size > hook_func_start_region.size) {
		std::cout << "[发生错误] patch_freeze_task failed: not enough kernel space." << std::endl;
		return 0;
	}
	vec_out_patch_bytes_data.push_back({ str_bytes, hook_func_start_addr });
	patch_jump(m_freeze_task, hook_func_start_addr, vec_out_patch_bytes_data);
	return shellcode_size;
}
