#ifndef _KERNEL_ROOT_KIT_PROCESS_CMDLINE_H_
#define _KERNEL_ROOT_KIT_PROCESS_CMDLINE_H_
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <set>
#include <map>

namespace kernel_root {
/**
 * @brief 查找所有符合指定 cmdline 字符串的进程 ID
 * 
 * 该函数会遍历 /proc 目录下的所有进程，读取每个进程的 cmdline 文件，根据参数 compare_full_agrc 决定是精确匹配 cmdline 还是只匹配首个参数。如果匹配成功，将对应的 pid 插入到输出集合 out 中。
 * 
 * @param str_root_key        用于root提权的密钥字符串
 * @param target_cmdline      目标进程的 cmdline 字符串
 * @param out                 输出参数，存放所有匹配到的进程 ID
 * @param compare_full_agrc   是否按完整参数列表进行匹配：
 *                            - true：读取整个参数列表，将各参数用空格拼接后再查找 target_cmdline 子串
 *                            - false：只读取第一个参数（程序名），与 target_cmdline 做 strcmp 完全匹配
 * @return 成功返回 ERR_NONE(0)；失败返回相应错误码（如无法打开 /proc 目录、提权失败等）
 */
ssize_t find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc = false);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc = false);

/**
 * @brief 等待并查找符合指定 cmdline 字符串的进程，带超时机制
 * 
 * 该函数会循环扫描 /proc 目录，直到找到第一个符合 target_cmdline 的进程或达到超时 timeout 为止。一旦找到，将通过引用参数 pid 返回该进程 ID，并立即返回。
 * 
 * @param str_root_key        用于root提权的密钥字符串
 * @param target_cmdline      目标进程的 cmdline 字符串
 * @param timeout             超时时间，单位为秒
 * @param pid                 输出参数，找到后设置为对应的进程 ID；若超时则保持为 0
 * @param compare_full_agrc   是否按完整参数列表进行匹配
 * @return 如果在超时前找到进程，返回 0 并通过 pid 返回匹配到的进程 ID；如果未找到返回负值错误码（如 ERR_PID_NOT_FOUND 表示超时未找到），其他错误码表示相关系统调用失败
 */
ssize_t wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t & pid, bool compare_full_agrc = false);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_wait_and_find_cmdline_process(const char* str_root_key, const char* target_cmdline, int timeout, pid_t &pid, bool compare_full_agrc = false);

/**
 * @brief 获取所有进程的 PID 与 cmdline 映射
 * 
 * 该函数会遍历 /proc 目录下的所有进程，对于每个进程读取其 cmdline 文件，如果 compare_full_agrc 为 true，则读取完整参数列表并用空格拼接后保存，否则只读取第一个参数（程序名）。最后将 pid 与对应的 cmdline 字符串保存到 pid_map 中。
 * 
 * @param str_root_key        用于root提权的密钥字符串
 * @param pid_map             输出参数，保存每个进程的 pid 及其 cmdline 字符串
 * @param compare_full_agrc   是否读取完整参数列表并拼接（true：拼接所有参数；false：只保存第一个参数）
 * @return 如果至少获取到一个进程返回 0；如果目录遍历完仍未读取到任何进程返回 ERR_PID_NOT_FOUND；其他错误码表示提权失败、打开目录失败等
 */
ssize_t get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc = false);
//fork安全版本（可用于安卓APP直接调用）
ssize_t safe_get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc = false);
}

#endif /* _KERNEL_ROOT_KIT_PROCESS_CMDLINE_H_ */
