#ifndef _KERNEL_ROOT_KIT_SU_INSTALL_HELPER_H_
#define _KERNEL_ROOT_KIT_SU_INSTALL_HELPER_H_
#include <iostream>
namespace kernel_root {
std::string install_su(const char* str_root_key, const char* base_path, ssize_t & err);

std::string safe_install_su(const char* str_root_key, const char* base_path, ssize_t& err);

ssize_t uninstall_su(const char* str_root_key, const char* base_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_uninstall_su(const char* str_root_key, const char* base_path);
}
#endif /* _KERNEL_ROOT_KIT_SU_INSTALL_HELPER_H_ */
