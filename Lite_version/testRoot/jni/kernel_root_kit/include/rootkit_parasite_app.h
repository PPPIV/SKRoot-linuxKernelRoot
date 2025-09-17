#pragma once
#include <iostream>
#include <set>
#include <map>
namespace kernel_root {
enum app_so_status {
    unknow = 0,
    running,
    not_running
};

/***************************************************************************
 * 预检查寄生APP（仅做检查，不植入）
 * 参数:
 *   str_root_key           ROOT 权限密钥文本
 *   target_pid_cmdline     目标进程的 cmdline
 *   output_so_full_path    输出：键为可寄生 so 的绝对路径，值为其状态（running / not_running）
 * 返回: ERR_NONE 表示成功; 其余为错误码
 ***************************************************************************/
ssize_t parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, app_so_status> &output_so_full_path);


/***************************************************************************
 * 开始植入寄生APP
 * 参数:
 *   str_root_key           ROOT 权限密钥文本
 *   target_pid_cmdline     目标进程的 cmdline
 *   original_so_full_path  待植入的 so 的绝对路径
 * 返回: ERR_NONE 表示成功; 其余为错误码
 ***************************************************************************/
ssize_t parasite_implant_app(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path);

/***************************************************************************
 * 开始植入寄生su环境
 * 参数:
 *   str_root_key           ROOT 权限密钥文本
 *   target_pid_cmdline     目标进程的 cmdline
 *   original_so_full_path  待植入的 so 的绝对路径
 *   su_folder              su 环境根目录
 * 返回: ERR_NONE 表示成功; 其余为错误码
 ***************************************************************************/
ssize_t parasite_implant_su_env(const char* str_root_key, const char* target_pid_cmdline, const char* original_so_full_path, std::string_view su_folder);

}
