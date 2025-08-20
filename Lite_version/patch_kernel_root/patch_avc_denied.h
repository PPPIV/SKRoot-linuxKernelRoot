#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchAvcDenied : public PatchBase
{
public:
	PatchAvcDenied(const std::vector<char>& file_buf, const SymbolRegion &avc_denied);
	~PatchAvcDenied();

	size_t patch_avc_denied_first_guide(const SymbolRegion& hook_func_start_region, size_t task_struct_offset_cred,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

	size_t patch_avc_denied_core(const SymbolRegion& hook_func_start_region, std::vector<patch_bytes_data>& vec_out_patch_bytes_data);
private:
	int get_need_read_cap_cnt();
	SymbolRegion m_avc_denied = {0};
};