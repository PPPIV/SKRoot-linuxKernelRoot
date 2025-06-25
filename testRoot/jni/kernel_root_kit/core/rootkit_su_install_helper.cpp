#include "kernel_root_kit_su_install_helper.h"

#include <string.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

#include "kernel_root_kit_umbrella.h"
#include "kernel_root_kit_su_exec_data.h"
#include "kernel_root_kit_log.h"

#include "../su/su_hide_path_utils.h"
namespace kernel_root {

bool write_su_exec(const char* target_path) {
    std::ofstream file(std::string(target_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        ROOT_PRINTF("Could not open file %s.\n", target_path);
        return false;
    }
    file.write(reinterpret_cast<char*>(su_exec_data), su_exec_file_size);
    file.close();
    return true;
}

std::string install_su(const char* str_root_key, const char* base_path, ssize_t& err) {
	if (kernel_root::get_root(str_root_key) != ERR_NONE) {
		err = ERR_NO_ROOT;
		return {};
	}

	//1.获取su_xxx隐藏目录
	std::string _su_hide_folder_path = kernel_root::su::find_su_hide_folder_path(str_root_key, base_path);
	if (_su_hide_folder_path.empty()) {
		//2.取不到，那就创建一个
		_su_hide_folder_path = kernel_root::su::create_su_hide_folder(str_root_key, base_path);
	}
	if (_su_hide_folder_path.empty()) {
		ROOT_PRINTF("su hide folder path empty error.\n");
		err = ERR_CREATE_SU_HIDE_FOLDER;
		return {};
	}
	std::string su_hide_full_path = _su_hide_folder_path + "/su";
	if(!std::filesystem::exists(su_hide_full_path.c_str())) {
		if (!write_su_exec(su_hide_full_path.c_str())) {
			ROOT_PRINTF("copy file error.\n");
			err = ERR_WRITE_SU_EXEC;
			return {};
		}
		if (!kernel_root::su::set_file_allow_access_mode(su_hide_full_path)) {
			ROOT_PRINTF("set file allow access mode error.\n");
			err = ERR_SET_FILE_ALLOW_ACCESS;
			return {};
		}
	}
	err = ERR_NONE;
	return su_hide_full_path;
}

std::string safe_install_su(const char* str_root_key, const char* base_path, ssize_t& err) {
	std::string su_hide_full_path;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t err;
		su_hide_full_path = install_su(str_root_key, base_path, err);
		write_errcode_from_child(finfo, err);
		write_string_from_child(finfo, su_hide_full_path);
		_exit(0);
		return 0;
	}
	err = ERR_NONE;
	if(!wait_fork_child_process(finfo)) {
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

ssize_t uninstall_su(const char* str_root_key, const char* base_path) {

	if (kernel_root::get_root(str_root_key) != ERR_NONE) {
		return ERR_NO_ROOT;
	}
	do {
		std::string _su_hide_path = kernel_root::su::find_su_hide_folder_path(str_root_key, base_path);
		if (_su_hide_path.empty()) {
			break;
		}
		remove(std::string(_su_hide_path + std::string("/su")).c_str());
	} while (1);
	return kernel_root::su::del_su_hide_folder(str_root_key, base_path) ? -512 : 0;
}

ssize_t safe_uninstall_su(const char* str_root_key, const char* base_path) {
	ssize_t err = ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = uninstall_su(str_root_key, base_path);
		write_errcode_from_child(finfo, err);
		_exit(0);
		return ERR_NONE;
	}
	if(!wait_fork_child_process(finfo)) {
		err = ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = ERR_READ_CHILD_ERRCODE;
		}
	}
	return err;
}
}



