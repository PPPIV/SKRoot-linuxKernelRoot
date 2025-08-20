#pragma once
#include <string>
#include <cstring>
#include <sys/stat.h>
#include <sys/xattr.h>

namespace kernel_root {

#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

#ifndef SELINUX_FILE_FLAG
#define SELINUX_FILE_FLAG "u:object_r:system_file:s0"
#endif

static inline bool set_file_allow_access_mode(const std::string& file_full_path) {
    if (chmod(file_full_path.c_str(), 0777) != 0) {
        return false;
    }
    if (setxattr(file_full_path.c_str(),
                 XATTR_NAME_SELINUX,
                 SELINUX_FILE_FLAG,
                 std::strlen(SELINUX_FILE_FLAG) + 1,
                 0) != 0) {
        return false;
    }
    return true;
}

} // namespace kernel_root
