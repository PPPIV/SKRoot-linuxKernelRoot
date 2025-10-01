#pragma once
#include <type_traits>
enum class KRootErr : ssize_t {
	ERR_NONE = 0,
	ERR_PARAM = -1000,
	ERR_NO_ROOT,
	ERR_WAIT_FORK_CHILD,
	ERR_READ_CHILD_ERRCODE,
	ERR_READ_CHILD_STRING,
	ERR_READ_CHILD_INT,
	ERR_READ_CHILD_UINT64,
	ERR_READ_CHILD_SET_ARR,
	ERR_READ_CHILD_MAP_I_S,
	ERR_READ_CHILD_MAP_S_I,
	ERR_READ_EOF,
	ERR_NO_MEM,
	ERR_EXECVE,
	ERR_KILL,
	ERR_APP_DIR,
	ERR_FIND_CMDLINE_PROC,
	ERR_EXIST_32BIT,
	ERR_NOT_EXIST_ORIGINAL_FILE,
	ERR_NOT_EXIST_IMPLANT_FILE,
	ERR_CHMOD,
	ERR_COPY_SELINUX,
	ERR_LINK_SO,
	ERR_CHECK_LINK_SO,
	ERR_NOT_FOUND_LIBC,
	ERR_LOAD_LIBC_FUNC_ADDR,
	ERR_INJECT_PROC64_ENV,
	ERR_INJECT_PROC64_SO,
	ERR_INJECT_PROC64_RUN_EXIT,
	ERR_LIBC_PATH_EMPTY,
	ERR_CREATE_SU_HIDE_FOLDER,
	ERR_DEL_SU_HIDE_FOLDER,
	ERR_WRITE_ROOT_SERVER,
	ERR_WRITE_SU_ENV_SO_FILE,
	ERR_WRITE_SU_EXEC,
	ERR_WRITE_UPX,
	ERR_SET_FILE_SELINUX,
	ERR_UPX,
	ERR_DEL_HIDE_FOLDER,
	ERR_POPEN,
	ERR_OPEN_FILE,
	ERR_OPEN_DIR,
	ERR_NOT_ELF64_FILE,
	ERR_DLOPEN_FILE,
	ERR_PID_NOT_FOUND,
};

constexpr ssize_t to_num(KRootErr err) noexcept {
    return static_cast<ssize_t>(err);
}

#define RETURN_ON_ERROR(expr)                                             \
    do {                                                                  \
        static_assert(                                                   \
            std::is_same<decltype(expr), KRootErr>::value,                \
            "RETURN_ON_ERROR: expr 必须返回 KRootErr"                       \
        );                                                                \
        KRootErr _err = (expr);                                            \
        if (_err != KRootErr::ERR_NONE)                                      \
            return _err;                                                  \
    } while (0)

#define BREAK_ON_ERROR(expr)                                              \
    do {                                                                  \
        static_assert(                                                   \
            std::is_same<decltype(expr), KRootErr>::value,                \
            "BREAK_ON_ERROR: expr 必须返回 KRootErr"                        \
        );                                                                \
        KRootErr _err = (expr);                                            \
        if (_err != KRootErr::ERR_NONE)                                      \
            break;                                                        \
    } while (0)