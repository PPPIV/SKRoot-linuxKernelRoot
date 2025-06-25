#ifndef _KERNEL_ROOT_KIT_COMMAND_H_
#define _KERNEL_ROOT_KIT_COMMAND_H_

#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

namespace kernel_root {
	//获取ROOT权限，返回值为0则代表成功
	ssize_t get_root(const char* str_root_key);

	//检查系统SELinux的是否为禁用状态
	bool is_enable_selinux();

	//执行root命令，返回值为0则代表成功
	std::string run_root_cmd(const char* str_root_key, const char* cmd, ssize_t & err);
}
#endif /* _KERNEL_ROOT_KIT_COMMAND_H_ */
