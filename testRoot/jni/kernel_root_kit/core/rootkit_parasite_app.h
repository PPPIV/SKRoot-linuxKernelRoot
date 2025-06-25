#ifndef _KERNEL_ROOT_KIT_PARASITE_APP_H_
#define _KERNEL_ROOT_KIT_PARASITE_APP_H_
#include <iostream>
#include <set>
#include <map>
namespace kernel_root {
enum app_so_status {
    unknow = 0,
    running,
    not_running
};

ssize_t parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, app_so_status> &output_so_full_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, app_so_status> &output_so_full_path);

#ifndef LIB_ROOT_SERVER_MODE
ssize_t parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, const char* su_path);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, const char* su_path);
#endif

ssize_t parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, std::string_view su_folder);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, std::string_view su_folder);
}
#endif /* _KERNEL_ROOT_KIT_PARASITE_APP_H_ */
