#include "rootkit_su_install_helper.h"

#include <string.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

#include "su/su_inline.h"
#include "rootkit_umbrella.h"
#if !defined(SU_MODE)
#include "rootkit_su_exec_data.h"
#endif
#include "rootkit_file_replace_string.h"
#include "rootkit_file_selinux_utils.h"

namespace kernel_root {
namespace {
constexpr const char* k_su_base_path = "/data";
static bool create_directory_if_not_exists(const std::string& dir_path) {
    try {
        if (!std::filesystem::exists(dir_path)) {
            return std::filesystem::create_directories(dir_path); // 递归创建
        }
        return true;
    } catch (const std::filesystem::filesystem_error& e) {
        return false;
    }
}

}
std::string get_su_hide_folder_path_string(const char* str_root_key) {
	std::string before16 = std::string(str_root_key).substr(0, 16);
	std::string file_path = k_su_base_path;
	file_path += "/" + before16;
	return file_path;
}

ssize_t unsafe_create_su_hide_folder(const char* str_root_key) {
	ssize_t err = kernel_root::get_root(str_root_key);
	RETURN_ON_ERROR(err);

	std::string file_path = get_su_hide_folder_path_string(str_root_key);
    // Check and create directories
    if (!create_directory_if_not_exists(file_path)) return ERR_CREATE_SU_HIDE_FOLDER;
    if (!set_file_allow_access_mode(file_path)) return ERR_SET_FILE_ALLOW_ACCESS;
    return ERR_NONE;
}

ssize_t safe_create_su_hide_folder(const char* str_root_key) {
	ssize_t err = ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_create_su_hide_folder(str_root_key);
		write_errcode_from_child(finfo, err);
		_exit(0);
		return ERR_NONE;
	}
	if(!is_fork_child_process_work_finished(finfo)) {
		err = ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = ERR_READ_CHILD_ERRCODE;
		}
	}
	return err;
}

ssize_t create_su_hide_folder(const char* str_root_key) {
	return safe_create_su_hide_folder(str_root_key);
}

ssize_t unsafe_del_su_hide_folder(const char* str_root_key) {
	ssize_t err = kernel_root::get_root(str_root_key);
	RETURN_ON_ERROR(err);
    std::string file_path = get_su_hide_folder_path_string(str_root_key);
	try {
		std::filesystem::remove_all(file_path);
	} catch (...) {
	}
	return std::filesystem::exists(file_path) ? ERR_DEL_SU_HIDE_FOLDER : ERR_NONE;
}

ssize_t safe_del_su_hide_folder(const char* str_root_key) {
	ssize_t err = ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_del_su_hide_folder(str_root_key);
		write_errcode_from_child(finfo, err);
		_exit(0);
		return ERR_NONE;
	}
	if(!is_fork_child_process_work_finished(finfo)) {
		err = ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = ERR_READ_CHILD_ERRCODE;
		}
	}
	return err;
}

ssize_t del_su_hide_folder(const char* str_root_key) {
	return safe_del_su_hide_folder(str_root_key);
}

}



