#pragma once
#include <iostream>
#include <vector>
#include "patch_base.h"
class PatchFreezeTask : public PatchBase
{
public:
	PatchFreezeTask(const PatchBase& patch_base, size_t freeze_task);
	~PatchFreezeTask();

	size_t patch_freeze_task(const SymbolRegion& hook_func_start_region, size_t task_struct_cred_offset,
		std::vector<patch_bytes_data>& vec_out_patch_bytes_data);

private:
	size_t m_freeze_task = 0;
};