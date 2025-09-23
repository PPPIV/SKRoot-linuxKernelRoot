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

#include "rootkit_umbrella.h"
#include "common/file_replace_string.h"
#include "common/file_utils.h"

#ifndef FOLDER_HEAD_ROOT_KEY_LEN
#define FOLDER_HEAD_ROOT_KEY_LEN 16
#endif
#define HIDE_DIR_FMT "/data/%s/"
using namespace file_utils;

namespace kernel_root {

std::string get_hide_dir_path(const char* str_root_key) {
    char hide_dir[1024] = {0};
	snprintf(hide_dir, sizeof(hide_dir), HIDE_DIR_FMT, std::string(str_root_key).substr(0, FOLDER_HEAD_ROOT_KEY_LEN).c_str());
	return hide_dir;
}

static ssize_t unsafe_create_su_hide_dir(const char* str_root_key) {
	RETURN_ON_ERROR(kernel_root::get_root(str_root_key));

	std::string dir_path = get_hide_dir_path(str_root_key);
    // Check and create directories
    if (!create_directory_if_not_exists(dir_path)) return ERR_CREATE_SU_HIDE_FOLDER;
    if (!set_file_selinux_access_mode(dir_path, SelinuxFileFlag::SELINUX_SYSTEM_FILE)) return ERR_SET_FILE_SELINUX;
    return ERR_NONE;
}

static ssize_t safe_create_su_hide_dir(const char* str_root_key) {
	ssize_t err = ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_create_su_hide_dir(str_root_key);
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

ssize_t create_su_hide_dir(const char* str_root_key) {
	return safe_create_su_hide_dir(str_root_key);
}

static ssize_t unsafe_del_su_hide_dir(const char* str_root_key) {
	RETURN_ON_ERROR(kernel_root::get_root(str_root_key));
    std::string dir_path = get_hide_dir_path(str_root_key);
	return delete_path(dir_path) ? ERR_DEL_SU_HIDE_FOLDER : ERR_NONE;
}

static ssize_t safe_del_su_hide_dir(const char* str_root_key) {
	ssize_t err = ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_del_su_hide_dir(str_root_key);
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

ssize_t del_su_hide_dir(const char* str_root_key) {
	return safe_del_su_hide_dir(str_root_key);
}

}



