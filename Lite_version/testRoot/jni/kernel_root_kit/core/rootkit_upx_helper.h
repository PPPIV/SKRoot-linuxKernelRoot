#pragma once
#include <iostream>
namespace kernel_root {
ssize_t upx_file(const char* str_root_key, const char* file_path);

ssize_t safe_upx_file(const char* str_root_key, const char* file_path);
}
