#pragma once
#include <iostream>
#include <filesystem>
#define IF_EXIT(cond) do { if (cond) { system("pause"); exit(0); } } while (0)

#define APPLY_PATCH(call_expr)                  \
    do {                                       \
        shellcode_size = (call_expr);          \
        IF_EXIT(!shellcode_size);              \
        next_hook_start_region.consume(shellcode_size); \
    } while (0)

struct patch_bytes_data {
	std::string str_bytes;
	size_t write_addr = 0;
};

static size_t patch_ret_cmd(const std::vector<char>& file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	vec_out_patch_bytes_data.push_back({ "C0035FD6", start });
	return start + 4;
}

static size_t patch_ret_1_cmd(const std::vector<char>& file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	vec_out_patch_bytes_data.push_back({ "200080D2C0035FD6", start });
	return start + 4 * 2;
}

static size_t patch_ret_0_cmd(const std::vector<char>& file_buf, size_t start, std::vector<patch_bytes_data>& vec_out_patch_bytes_data) {
	vec_out_patch_bytes_data.push_back({ "E0031F2AC0035FD6", start });
	return start + 4 * 2;
}