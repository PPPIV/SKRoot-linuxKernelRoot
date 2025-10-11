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
namespace fs = std::filesystem;

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
		finfo.close_all();
		_exit(0);
		return KRootErr::ERR_NONE;
	}
	if(!read_errcode_from_child(finfo, err)) {
		err = KRootErr::ERR_READ_CHILD_ERRCODE;
	}
	int status = 0; waitpid(finfo.child_pid, &status, 0);
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
		finfo.close_all();
		_exit(0);
		return KRootErr::ERR_NONE;
	}
	if(!read_errcode_from_child(finfo, err)) {
		err = KRootErr::ERR_READ_CHILD_ERRCODE;
	}
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr del_su_hide_dir(const char* str_root_key) {
	return safe_del_su_hide_dir(str_root_key);
}

static KRootErr unsafe_clean_older_hide_dir(const char* root_key) {
    RETURN_ON_ERROR(get_root(root_key));

    fs::path hide_dir_path = get_hide_dir_path(root_key);

    fs::path p = hide_dir_path;
    if (!p.has_filename()) p = p.parent_path();

    fs::path base_dir_path = p.parent_path();
    std::string hide_name = p.filename().string();
    size_t hide_name_len    = hide_name.length();

    fs::path skroot_flag_path   = get_skroot_flag_path(root_key);
    std::string flag_file_name  = skroot_flag_path.filename().string();// skroot

    DIR* dir = opendir(base_dir_path.c_str());
    if (!dir) return KRootErr::ERR_OPEN_DIR;

    std::vector<fs::path> dirs_to_delete;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        if (name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'))) continue;
        if (entry->d_type != DT_DIR) continue;
        if (strlen(name) != hide_name_len) continue;

        fs::path candidate_dir = base_dir_path / name;
        fs::path candidate_flag = candidate_dir / flag_file_name;
        if (!file_exists(candidate_flag.string())) continue;

        fs::path sibling_hide_dir_path = candidate_dir;
        if (hide_dir_path.lexically_normal() == sibling_hide_dir_path.lexically_normal()) continue;

        dirs_to_delete.emplace_back(std::move(candidate_dir));
    }
    closedir(dir);

    for (const auto& dir_path : dirs_to_delete) {
        delete_path(dir_path.string());
    }
    return KRootErr::ERR_NONE;
}

static KRootErr safe_clean_older_hide_dir(const char* str_root_key) {
	KRootErr err = KRootErr::ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_clean_older_hide_dir(str_root_key);
		write_errcode_from_child(finfo, err);
		finfo.close_all();
		_exit(0);
		return KRootErr::ERR_NONE;
	}

	if(!read_errcode_from_child(finfo, err)) {
		err = KRootErr::ERR_READ_CHILD_ERRCODE;
	}
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr clean_older_hide_dir(const char* str_root_key) {
	return safe_clean_older_hide_dir(str_root_key);
}
}



