#pragma once
#include <unistd.h>
#include <vector>

#include "rootkit_err_def.h"
namespace kernel_root {
typedef enum {
    api_offset_read_only_read_file = 0,
    api_offset_read_only_read_self_mem,
    api_offset_read_all
} api_offset_read_mode;

/***************************************************************************
 * 向 64 位远程进程的 PATH 环境变量添加路径
 * 参数:
 *   str_root_key		ROOT 权限密钥文本
 *   target_pid			目标进程 PID
 *   add_path			要追加到 PATH 的路径字符串
 *   api_offset_mode	API偏移读取模式
 * 返回: ERR_NONE 表示成功；其余为错误码
 ***************************************************************************/
KRootErr inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char *add_path,
	api_offset_read_mode api_offset_mode = api_offset_read_all);

/***************************************************************************
 * 杀死指定进程
 * 参数:
 *   str_root_key	ROOT 权限密钥文本
 *   pid			要终止的进程 ID
 * 返回: ERR_NONE 表示成功；其余为错误码
 ***************************************************************************/
KRootErr kill_process(const char* str_root_key, pid_t pid);
}