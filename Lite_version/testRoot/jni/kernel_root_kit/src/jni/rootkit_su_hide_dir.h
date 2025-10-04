#pragma once
#include <iostream>

namespace kernel_root {
KRootErr create_su_hide_dir(const char* str_root_key);

KRootErr del_su_hide_dir(const char* str_root_key);

KRootErr clean_older_hide_dir(const char* root_key);
} // namespace kernel_root
