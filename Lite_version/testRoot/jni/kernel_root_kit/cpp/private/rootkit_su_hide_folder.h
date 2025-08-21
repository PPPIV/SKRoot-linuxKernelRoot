#pragma once
#include <iostream>

namespace kernel_root {
std::string get_su_hide_folder_path_string(const char* str_root_key);

ssize_t create_su_hide_folder(const char* str_root_key);

ssize_t del_su_hide_folder(const char* str_root_key);
} // namespace kernel_root
