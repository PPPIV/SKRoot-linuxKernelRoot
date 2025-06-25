#include "kernel_root_kit_upx_helper.h"
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <random>
#include <filesystem>
#include <sys/stat.h>
#include <sys/types.h>

#include "kernel_root_kit_umbrella.h"
#include "kernel_root_kit_upx_data.h"
#include "kernel_root_kit_log.h"
#include "../su/su_hide_path_utils.h"

namespace kernel_root {

bool write_upx_exec(const char* target_path) {
    std::ofstream file(std::string(target_path), std::ios::binary | std::ios::out);
    if (!file.is_open()) {
        ROOT_PRINTF("Could not open file %s.\n", target_path);
        return false;
    }
    file.write(reinterpret_cast<char*>(upx_file_data), upx_file_size);
    file.close();
    return true;
}

ssize_t upx_file(const char* str_root_key, const char* file_path) {
    if (kernel_root::get_root(str_root_key) != ERR_NONE) {
        return ERR_NO_ROOT;
    }
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
	ssize_t err = kernel_root::safe_root_exec_process(str_root_key, sstr.str().c_str());
	do {
		if(err != ERR_NONE) {
			break;
		}
		if(!std::filesystem::exists(file_path_upx)) {
			err = ERR_UPX;
			break;
		}
		remove(file_path);
		rename(file_path_upx.c_str(), file_path);

	} while(0);
	remove(upx_full_path.c_str());
	remove(file_path_upx.c_str());
    return ERR_NONE;
}

ssize_t safe_upx_file(const char* str_root_key, const char* file_path) {
	ssize_t err = ERR_NONE;
	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		err = upx_file(str_root_key, file_path);
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



