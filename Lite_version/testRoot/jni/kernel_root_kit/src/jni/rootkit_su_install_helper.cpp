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
#include "rootkit_path.h"
#include "rootkit_fork_helper.h"
#include "rootkit_su_hide_dir.h"
#include "common/file_replace_string.h"
#include "common/file_utils.h"

using namespace file_utils;
namespace kernel_root {

#ifdef SU_EXEC_DATA
static bool write_su_exec(const char* str_root_key, const char* target_path) {
	std::shared_ptr<char> sp_su_exec_file_data(new (std::nothrow) char[su_exec_file_size], std::default_delete<char[]>());
	if(!sp_su_exec_file_data) {
		return false;
	}
	memcpy(sp_su_exec_file_data.get(), reinterpret_cast<char*>(su_exec_data), su_exec_file_size);

	// write root key
	if(!replace_feature_string_in_buf(const_cast<char*>(static_inline_su_rootkey), sizeof(static_inline_su_rootkey), str_root_key, sp_su_exec_file_data.get(), su_exec_file_size)) {
		return false;
	}

    std::ofstream file(std::string(target_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        return false;
    }
    file.write(sp_su_exec_file_data.get(), su_exec_file_size);
    file.close();
    return true;
}

static KRootErr unsafe_install_su(const char* str_root_key, std::string& out_su_full_path) {
	RETURN_ON_ERROR(kernel_root::get_root(str_root_key));
	std::string su_full_path = kernel_root::get_su_hide_path(str_root_key);
	if (!write_su_exec(str_root_key, su_full_path.c_str())) return KRootErr::ERR_WRITE_SU_EXEC;
	if (!set_file_selinux_access_mode(su_full_path.c_str(), SelinuxFileFlag::SELINUX_SYSTEM_FILE)) return KRootErr::ERR_SET_FILE_SELINUX;
	
	out_su_full_path = su_full_path;
	return KRootErr::ERR_NONE;
}

static KRootErr safe_install_su(const char* str_root_key, std::string& out_su_full_path) {
	out_su_full_path.clear();
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		KRootErr err = unsafe_install_su(str_root_key, out_su_full_path);
		write_errcode_from_child(finfo, err);
		write_string_from_child(finfo, out_su_full_path);
		finfo.close_all();
		_exit(0);
		return KRootErr::ERR_NONE;
	}
	KRootErr err = KRootErr::ERR_NONE;
	if(!read_errcode_from_child(finfo, err)) {
		err = KRootErr::ERR_READ_CHILD_ERRCODE;
	} else if(!read_string_from_child(finfo, out_su_full_path)) {
		err = KRootErr::ERR_READ_CHILD_STRING;
	}
	int status = 0; waitpid(finfo.child_pid, &status, 0);
	return err;
}

KRootErr install_su_with_cb(const char* str_root_key, void (*cb)(const char* su_full_path)) {
	RETURN_ON_ERROR(clean_older_hide_dir(str_root_key));
	RETURN_ON_ERROR(create_su_hide_dir(str_root_key));
	std::string su_path;
	RETURN_ON_ERROR(safe_install_su(str_root_key, su_path));
	cb(su_path.c_str());
	return KRootErr::ERR_NONE;
}
#endif

KRootErr uninstall_su(const char* str_root_key) {
	clean_older_hide_dir(str_root_key);
	return del_su_hide_dir(str_root_key);
}

}



