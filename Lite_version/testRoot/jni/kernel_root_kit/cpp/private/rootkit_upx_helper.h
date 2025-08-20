#pragma once
#include <iostream>
namespace kernel_root {
#if !defined(SU_MODE)
/***************************************************************************
 * 使用 UPX 压缩指定文件
 * 参数:
 *   str_root_key   ROOT 权限密钥文本
 *   file_path      目标文件的绝对路径
 * 返回: ERR_NONE 表示压缩成功；其余为错误码
 ***************************************************************************/
ssize_t upx_file(const char* str_root_key, const char* file_path);
#endif
}
