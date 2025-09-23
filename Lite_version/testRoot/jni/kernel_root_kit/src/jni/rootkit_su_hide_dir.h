#pragma once
#include <iostream>

namespace kernel_root {
std::string get_hide_dir_path(const char* str_root_key);

ssize_t create_su_hide_dir(const char* str_root_key);

ssize_t del_su_hide_dir(const char* str_root_key);
} // namespace kernel_root
