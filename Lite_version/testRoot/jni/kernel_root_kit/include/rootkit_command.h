#pragma once
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

namespace kernel_root {
/***************************************************************************
 * 获取ROOT权限
 * 参数: str_root_key ROOT权限密钥文本
 * 返回: ERR_NONE 表示成功；其他值为错误码
 ***************************************************************************/
ssize_t get_root(const char* str_root_key);

/***************************************************************************
 * 判断系统SELinux是否禁用
 * 参数: str_root_key ROOT权限密钥文本
 * 返回: true: 表示SELinux启用，否则为禁用
 ***************************************************************************/
bool is_enable_selinux();

/***************************************************************************
 * 执行ROOT命令
 * 参数: str_root_key ROOT权限密钥文本
 * 返回: 运行输出
 ***************************************************************************/
std::string run_root_cmd(const char* str_root_key, const char* cmd, ssize_t & err);
}
