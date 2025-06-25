#include "kernel_root_kit_exec_process.h"
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include "kernel_root_kit_umbrella.h"

namespace kernel_root {
	ssize_t root_exec_process(const char* str_root_key, const char *file_path) {
		int err = ERR_NONE;
		if (file_path == NULL || strlen(file_path) == 0) { return ERR_PARAM; }

		if (kernel_root::get_root(str_root_key) != ERR_NONE) {
			return ERR_NO_ROOT;
		}

		char *buf1 = strdup(file_path);
		size_t argc = 0;
		char *saveptr;
		for (char *tok = strtok_r(buf1, " ", &saveptr);
			tok;
			tok = strtok_r(NULL, " ", &saveptr)) {
			argc++;
		}
		free(buf1);

		char *buf2 = strdup(file_path);
		char **argv = static_cast<char**>(calloc(argc + 1, sizeof(char*)));
		size_t idx = 0;
		for (char *tok = strtok_r(buf2, " ", &saveptr);
			tok;
			tok = strtok_r(NULL, " ", &saveptr)) {
			argv[idx++] = tok;
		}
		argv[idx] = NULL;
		execve(argv[0], argv, environ);
		err = ERR_EXECVE * EXTRA_ERR_MULT + -errno;
		free(argv);
		free(buf2);
		return err;
	}

	ssize_t safe_root_exec_process(
		const char* str_root_key,
		const char *file_path) {
		if (file_path == NULL || strlen(file_path) == 0) { return ERR_PARAM; }
		
		fork_pipe_info finfo;
		if (fork_pipe_child_process(finfo)) {
			ssize_t err = root_exec_process(str_root_key, file_path);
			write_errcode_from_child(finfo, err);
			_exit(0);
			return ERR_NONE;
		}
		ssize_t err = ERR_NONE;
		if (!wait_fork_child_process(finfo)) {
			err = ERR_WAIT_FORK_CHILD;
		} else if (!read_errcode_from_child(finfo, err)) {
			if(err == ERR_READ_EOF) {
				return ERR_NONE;
			}
		}
		return err;
	}
}
