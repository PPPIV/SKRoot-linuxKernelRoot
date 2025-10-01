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
#include "rootkit_fork_helper.h"
#include "rootkit_path.h"
#include "common/file_replace_string.h"
#include "common/file_utils.h"

using namespace file_utils;

namespace kernel_root {
static KRootErr unsafe_create_su_hide_dir(const char* str_root_key) {
	RETURN_ON_ERROR(get_root(str_root_key));

	std::string dir_path = get_hide_dir_path(str_root_key);
    // Check and create directories
    if (!create_directory_if_not_exists(dir_path.c_str())) return KRootErr::ERR_CREATE_SU_HIDE_FOLDER;
    if (!set_file_selinux_access_mode(dir_path.c_str(), SelinuxFileFlag::SELINUX_SYSTEM_FILE)) return KRootErr::ERR_SET_FILE_SELINUX;

	std::string skroot_flag_path = get_skroot_flag_path(str_root_key);
    if(!create_empty_file(skroot_flag_path.c_str())) return KRootErr::ERR_OPEN_FILE;
    return KRootErr::ERR_NONE;
}

static KRootErr safe_create_su_hide_dir(const char* str_root_key) {
	KRootErr err = KRootErr::ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_create_su_hide_dir(str_root_key);
		write_errcode_from_child(finfo, err);
		_exit(0);
		return KRootErr::ERR_NONE;
	}
	if(!is_fork_child_process_work_finished(finfo)) {
		err = KRootErr::ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = KRootErr::ERR_READ_CHILD_ERRCODE;
		}
	}
	return err;
}

KRootErr create_su_hide_dir(const char* str_root_key) {
	return safe_create_su_hide_dir(str_root_key);
}

static KRootErr unsafe_del_su_hide_dir(const char* str_root_key) {
	RETURN_ON_ERROR(get_root(str_root_key));
    std::string dir_path = get_hide_dir_path(str_root_key);
	return delete_path(dir_path) ? KRootErr::ERR_NONE : KRootErr::ERR_DEL_SU_HIDE_FOLDER;
}

static KRootErr safe_del_su_hide_dir(const char* str_root_key) {
	KRootErr err = KRootErr::ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_del_su_hide_dir(str_root_key);
		write_errcode_from_child(finfo, err);
		_exit(0);
		return KRootErr::ERR_NONE;
	}
	if(!is_fork_child_process_work_finished(finfo)) {
		err = KRootErr::ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, err)) {
			err = KRootErr::ERR_READ_CHILD_ERRCODE;
		}
	}
	return err;
}

KRootErr del_su_hide_dir(const char* str_root_key) {
	return safe_del_su_hide_dir(str_root_key);
}

}



