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
#include "rootkit_su_hide_folder.h"
#include "rootkit_file_replace_string.h"
#include "rootkit_file_selinux_utils.h"

namespace kernel_root {
#if !defined(SU_MODE)
bool write_su_exec(const char* str_root_key, const char* target_path) {
	std::shared_ptr<char> sp_su_exec_file_data(new (std::nothrow) char[su_exec_file_size], std::default_delete<char[]>());
	if(!sp_su_exec_file_data) {
		return ERR_NO_MEM;
	}
	memcpy(sp_su_exec_file_data.get(), reinterpret_cast<char*>(su_exec_data), su_exec_file_size);

	// write root key
	if(!replace_feature_string_in_buf(const_cast<char*>(static_inline_su_rootkey), sizeof(static_inline_su_rootkey), str_root_key, sp_su_exec_file_data.get(), su_exec_file_size)) {
		return ERR_WRITE_ROOT_SERVER;
	}

    std::ofstream file(std::string(target_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        return false;
    }
    file.write(sp_su_exec_file_data.get(), su_exec_file_size);
    file.close();
    return true;
}

std::string unsafe_install_su(const char* str_root_key, ssize_t& err) {
	if (kernel_root::get_root(str_root_key) != ERR_NONE) {
		err = ERR_NO_ROOT;
		return {};
	}
	std::string su_hide_full_path = get_su_hide_folder_path_string(str_root_key) + "/su";
	if(!std::filesystem::exists(su_hide_full_path.c_str())) {
		if (!write_su_exec(str_root_key, su_hide_full_path.c_str())) {
			err = ERR_WRITE_SU_EXEC;
			return {};
		}
		if (!kernel_root::set_file_allow_access_mode(su_hide_full_path)) {
			err = ERR_SET_FILE_ALLOW_ACCESS;
			return {};
		}
	}
	err = ERR_NONE;
	return su_hide_full_path;
}

std::string safe_install_su(const char* str_root_key, ssize_t& err) {
	std::string su_hide_full_path;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t err;
		su_hide_full_path = unsafe_install_su(str_root_key, err);
		write_errcode_from_child(finfo, err);
		write_string_from_child(finfo, su_hide_full_path);
		_exit(0);
		return 0;
	}
	err = ERR_NONE;
	if(!is_fork_child_process_work_finished(finfo)) {
		err = ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = ERR_READ_CHILD_ERRCODE;
		} else if(!read_string_from_child(finfo, su_hide_full_path)) {
			err = ERR_READ_CHILD_STRING;
		}
	}
	return su_hide_full_path;
}

std::string install_su(const char* str_root_key, ssize_t& err) {
	err = create_su_hide_folder(str_root_key);
	if(err != ERR_NONE) {
		return {};
	}
	return safe_install_su(str_root_key, err);
}

ssize_t uninstall_su(const char* str_root_key) {
	return del_su_hide_folder(str_root_key);
}
#endif
}



