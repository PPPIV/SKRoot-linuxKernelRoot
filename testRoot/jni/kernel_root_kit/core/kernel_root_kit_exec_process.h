#ifndef _KERNEL_ROOT_KIT_EXEC_PROCESS_H_
#define _KERNEL_ROOT_KIT_EXEC_PROCESS_H_
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

namespace kernel_root {
	//以root身份直接执行程序
	ssize_t root_exec_process(const char* str_root_key, const char *file_path);
	//fork安全版本（可用于安卓APP直接调用）
	ssize_t safe_root_exec_process(const char* str_root_key, const char *file_path);
}
#endif /* _KERNEL_ROOT_KIT_EXEC_PROCESS_H_ */
