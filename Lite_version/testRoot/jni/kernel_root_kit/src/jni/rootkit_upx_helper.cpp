#include "rootkit_upx_helper.h"
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <random>
#include <sstream>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

#include "rootkit_umbrella.h"
#include "3rdparty\upx\upx_exec_data.h"

namespace kernel_root {
static bool write_upx_exec(const char* target_path) {
    std::ofstream file(std::string(target_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        return false;
    }
    file.write(reinterpret_cast<char*>(upx_file_data), upx_file_size);
    file.close();
    return true;
}

static ssize_t unsafe_upx_file(const char* str_root_key, const char* file_path) {
	RETURN_ON_ERROR(kernel_root::get_root(str_root_key));
	std::filesystem::path path(file_path);
	std::string folder_path = path.parent_path().string();
	std::string upx_full_path = folder_path  + "/upx";

	if(!write_upx_exec(upx_full_path.c_str())) {
		return ERR_WRITE_UPX; 
	}

	std::string file_path_upx = file_path;
	file_path_upx += ".upx";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(1, 9);
    int random_number = dist(gen);
	std::stringstream sstr;
	sstr << " -" << random_number << " -o " << file_path_upx << " " << file_path;
	BREAK_ON_ERROR(kernel_root::root_exec_process(str_root_key, sstr.str().c_str()));
	ssize_t err = ERR_NONE;
	do {
		if(!std::filesystem::exists(file_path_upx)) {
			err = ERR_UPX;
			break;
		}
		remove(file_path);
		rename(file_path_upx.c_str(), file_path);

	} while(0);
	remove(upx_full_path.c_str());
	remove(file_path_upx.c_str());
    return err;
}

static ssize_t safe_upx_file(const char* str_root_key, const char* file_path) {
	ssize_t err = ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = unsafe_upx_file(str_root_key, file_path);
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

ssize_t upx_file(const char* str_root_key, const char* file_path) {
	return safe_upx_file(str_root_key, file_path);
}
}



