#include "kernel_root_kit_command.h"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/prctl.h>

#include "kernel_root_kit_umbrella.h"

namespace kernel_root {
	ssize_t get_root(const char* str_root_key) {
		if(getuid() == 0) { return ERR_NONE; }
		if (str_root_key == NULL) { return ERR_PARAM; }
		syscall(__NR_execve, str_root_key, NULL, NULL);
		if(getuid() != 0) { return ERR_NO_ROOT; }
        return ERR_NONE;
	}

	bool is_enable_selinux() {
		int cnt = 0;
		DIR* dir = opendir("/");
		if (NULL != dir) {
			struct dirent* ptr = NULL;
			while ((ptr = readdir(dir)) != NULL) {
				if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
					continue;
				}
				cnt++;
			}
			closedir(dir);
		}
		return cnt > 5 ? false : true;
	}

	std::string run_root_cmd(const char* str_root_key, const char* cmd, ssize_t & err) {
		if (str_root_key == NULL || cmd == NULL || strlen(cmd) == 0) {
			err = ERR_PARAM;
			return {};
		}
		//把错误信息也打出来
		std::string cmd_add_err_info = cmd;
		cmd_add_err_info += " 2>&1";

		std::string result;
		fork_pipe_info finfo;
		if(fork_pipe_child_process(finfo)) {
			err = ERR_NONE;
			do {
				if (get_root(str_root_key) != ERR_NONE) {
					err = ERR_NO_ROOT;
					break;
				}
				FILE * fp = popen(cmd_add_err_info.c_str(), "r");
				if(!fp) {
					err = ERR_POPEN;
					break;
				}
				int pip = fileno(fp);
				while(true) {
					char rbuf[1024] = {0};
					ssize_t r = read(pip, rbuf, sizeof(rbuf));
					if (r == -1 && errno == EAGAIN) {
						continue; //意味着现在没有可用的数据,以后再试一次
					} else if(r > 0) {
						std::string str_convert(rbuf, r);
						result += str_convert;
					} else {
						break;
					}
				}
				pclose(fp);
			} while(0);
			write_errcode_from_child(finfo, err);
			write_string_from_child(finfo, result);
			_exit(0);
			return {};
		}
		err = ERR_NONE;
		if(!wait_fork_child_process(finfo)) {
			err = ERR_WAIT_FORK_CHILD;
		} else {
			if(!read_errcode_from_child(finfo, err)) {
				err = ERR_READ_CHILD_ERRCODE;
			} else if(!read_string_from_child(finfo, result)) {
				err = ERR_READ_CHILD_STRING;
			}
		}
		return result;
	}
}
