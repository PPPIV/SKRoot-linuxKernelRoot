#include "kernel_root_kit_process64_inject.h"
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <dlfcn.h>
#include <signal.h>

#include <memory>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <map>

#include "kernel_root_kit_umbrella.h"
#include "kernel_root_kit_ptrace_arm64_utils.h"
#include "kernel_root_kit_maps_helper.h"
#include "kernel_root_kit_elf64_symbol_parser.h"
#include "kernel_root_kit_log.h"

namespace kernel_root {

int _load_libc64_modify_env_func_addr(
	const char* str_root_key,
	const char* so_path,
	api_offset_read_mode api_mode,
	size_t& p_mmap_offset,
	size_t& p_munmap_offset,
	size_t& p_getenv_offset,
	size_t& p_setenv_offset) {

	int ret = ERR_NONE;
	std::map<std::string, uint64_t> func_symbol_map;
	func_symbol_map["getenv"] = 0;
	func_symbol_map["setenv"] = 0;
	func_symbol_map["mmap"] = 0;
	func_symbol_map["munmap"] = 0;

	do {
		if(api_mode == api_offset_read_mode::only_read_myself_mem || api_mode == api_offset_read_mode::all) {
			bool is_already_loaded = !!get_module_base(-1, so_path);
			if (is_already_loaded) {
				ROOT_PRINTF("myself have this so.\n");
				ret = find_mem_elf64_symbol_address(so_path, func_symbol_map);
				break;
			}
		}
		if(api_mode == api_offset_read_mode::only_read_file || api_mode == api_offset_read_mode::all) {
			ret = read_elf64_file_symbol_addr(so_path, func_symbol_map);
			break;
		}
	} while (0);
	
	p_mmap_offset = func_symbol_map["mmap"];
	p_munmap_offset = func_symbol_map["munmap"];
	p_getenv_offset = func_symbol_map["getenv"];
	p_setenv_offset = func_symbol_map["setenv"];
	return ret;
}

ssize_t inject_process_env64_PATH(
	int target_pid,
	const char* libc64_so_path,
	size_t& p_mmap_offset,
	size_t& p_munmap_offset,
	size_t& p_getenv_offset,
	size_t& p_setenv_offset,
	const char* add_path) {
	size_t input_env_buf_size = 0;
	ssize_t ret = ERR_INJECT_PROC64_ENV;
	size_t remote_libc64_handle = 0;
	size_t mmap_addr, munmap_addr, getenv_addr, setenv_addr;
	uint8_t* map_base;

	struct pt_regs regs, original_regs;
	unsigned long parameters[10];
	const char* str_flag_path = "PATH";
	char* ret_getenv = NULL;
	size_t tmp_read_byte_index = 0;
	char tmp_read_byte[2] = { 0 };
	std::string str_cur_path;
	//将要注入的cmd命令写入前面mmap出来的内存

	input_env_buf_size = (strlen(add_path) + 1 / getpagesize()) * getpagesize();
	if((strlen(add_path) + 1) % getpagesize()) {
		input_env_buf_size += getpagesize();
	}
	if(input_env_buf_size == 0) {
		input_env_buf_size = getpagesize();
	}

	ROOT_PRINTF("[+] Injecting process: %d\n", target_pid);

	//①ATTATCH，指定目标进程，开始调试  
	if (ptrace_attach(target_pid) == -1) {
		goto _ret;
	}

	//②GETREGS，获取目标进程的寄存器，保存现场  
	if (ptrace_getregs(target_pid, &regs) == -1) {
		goto _deatch;
	}

	/* save original registers */
	memcpy(&original_regs, &regs, sizeof(regs));

	//③获取目的进程的mmap函数的地址，以便为libxxx.so分配内存  

	/*
		需要对(void*)mmap进行说明：这是取得inject本身进程的mmap函数的地址，由于mmap函数在libc.so
		库中，为了将libxxx.so加载到目的进程中，就需要使用目的进程的mmap函数，所以需要查找到libc.so库在目的进程的起始地址。
	*/


	//获取远程pid的某个模块的起始地址  
	remote_libc64_handle = (size_t)get_module_base(target_pid, libc64_so_path);
	if (remote_libc64_handle == 0) {
		ROOT_PRINTF("[+] get_module_base failed.\n");
		goto _deatch;
	}
	mmap_addr = p_mmap_offset ? remote_libc64_handle + p_mmap_offset : 0;
	munmap_addr = p_munmap_offset ? remote_libc64_handle + p_munmap_offset : 0;
	getenv_addr = p_getenv_offset ? remote_libc64_handle + p_getenv_offset : 0;
	setenv_addr = p_setenv_offset ? remote_libc64_handle + p_setenv_offset : 0;

	ROOT_PRINTF("[+] Remote mmap address: %p\n", (void*)mmap_addr);
	ROOT_PRINTF("[+] Remote munmap address: %p\n", (void*)munmap_addr);
	ROOT_PRINTF("[+] Remote getenv address: %p\n", (void*)getenv_addr);
	ROOT_PRINTF("[+] Remote setenv address: %p\n", (void*)setenv_addr);

	/* call mmap (null, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
							 MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	匿名申请一块0x4000大小的内存
	*/
	parameters[0] = 0;  // addr      
	parameters[1] = (unsigned long)(input_env_buf_size); // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot      
	parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags      
	parameters[4] = 0; //fd      
	parameters[5] = 0; //offset      

	if (ptrace_call_wrapper(target_pid, "mmap", (void*)mmap_addr, parameters, 6, &regs) == -1) {
		goto _recovery;
	}

	//⑤从寄存器中获取mmap函数的返回值，即申请的内存首地址：  
	map_base = (uint8_t*)ptrace_retval(&regs);

	//写PATH标志进mmap出来的内存
	ptrace_writedata(target_pid, map_base, (uint8_t*)str_flag_path, strlen(str_flag_path) + 1);


	parameters[0] = (unsigned long)map_base;
	//执行getenv，等于getenv("PATH");
	if (ptrace_call_wrapper(target_pid, "getenv", (void*)getenv_addr, parameters, 1, &regs) == -1) {
		goto _recovery;
	}
	ret_getenv = (char*)ptrace_retval(&regs);
	if (!ret_getenv) {
		//getenv error
		ROOT_PRINTF("getenv error\n");
		goto _recovery;
	}
	str_cur_path += add_path;
	str_cur_path += ":";
	do {
		tmp_read_byte[0] = '\x00';
		ptrace_readdata(target_pid, (uint8_t*)((size_t)ret_getenv + tmp_read_byte_index), (uint8_t*)&tmp_read_byte, 1);

		tmp_read_byte_index++;
		str_cur_path += tmp_read_byte;
	} while (tmp_read_byte[0] != '\x00');


	ROOT_PRINTF("[+] Remote cur path: %s\n", str_cur_path.c_str());

	//写PATH变量进mmap出来的内存
	ptrace_writedata(target_pid, map_base + strlen(str_flag_path) + 1, (uint8_t*)str_cur_path.c_str(), str_cur_path.length() + 1);


	parameters[0] = (unsigned long)map_base;
	parameters[1] = (unsigned long)(map_base + strlen(str_flag_path) + 1);
	parameters[2] = 1;
	//执行setenv，等于setenv("PATH", "XXXXX", 1);
	if (ptrace_call_wrapper(target_pid, "setenv", (void*)setenv_addr, parameters, 3, &regs) == -1) {
		goto _recovery;
	}
	if (ptrace_retval(&regs)) {
		//setenv error
		ROOT_PRINTF("setenv error\n");
		goto _recovery;
	}

	//解除绑定内存（不知道为什么解除内存绑定会导致对方程序crash）
	parameters[0] = (unsigned long)map_base;// addr
	parameters[1] = (unsigned long)(input_env_buf_size); // size

	if (ptrace_call_wrapper(target_pid, "munmap", (void*)munmap_addr, parameters, 2, &regs) == -1) {
		goto _recovery;
	}

	ret = 0;
	//ROOT_PRINTF("Press enter to detach\n");
	//getchar();

	/* restore */
	//⑪恢复现场并退出ptrace:  
_recovery:	ptrace_setregs(target_pid, &original_regs);
_deatch:ptrace_detach(target_pid);

_ret:	return ret;
}

ssize_t inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char* add_path,
	api_offset_read_mode api_mode /* = api_offset_read_mode::all*/) {
	if (kernel_root::get_root(str_root_key) != ERR_NONE) {
		return ERR_NO_ROOT;
	}

	/*
	安卓:
	/apex/com.android.runtime/lib64/bionic/libc.so
	/apex/com.android.runtime/bin/linker64

	Linux进程:
	/system/lib64/libc.so
	/system/bin/linker64

	init进程
	/system/lib64/bootstrap/libc.so
	/system/lib64/bootstrap/linker64
	*/
	std::string target_process_libc_so_path = find_process_libc_so_path(target_pid);
	if (target_process_libc_so_path.empty()) {
		return ERR_LIBC_PATH_EMPTY;
	}
	ROOT_PRINTF("target_process_libc_so_path:%s\n", target_process_libc_so_path.c_str());

	size_t p_mmap_offset;
	size_t p_munmap_offset;
	size_t p_getenv_offset;
	size_t p_setenv_offset;
	int ret = _load_libc64_modify_env_func_addr(
		str_root_key,
		target_process_libc_so_path.c_str(),
		api_mode,
		p_mmap_offset,
		p_munmap_offset,
		p_getenv_offset,
		p_setenv_offset);
	if (ret != ERR_NONE) {
		ROOT_PRINTF("_load_libc64_modify_env_func_addr error:%d\n", ret);
		return ret;
	}
	ROOT_PRINTF("p_mmap_offset:%zu\n", p_mmap_offset);
	ROOT_PRINTF("p_munmap_offset:%zu\n", p_munmap_offset);
	ROOT_PRINTF("p_getenv_offset:%zu\n", p_getenv_offset);
	ROOT_PRINTF("p_setenv_offset:%zu\n", p_setenv_offset);
	if(!p_mmap_offset || !p_munmap_offset || !p_getenv_offset || !p_setenv_offset) {
		return ERR_LOAD_LIBC_FUNC_ADDR;
	}
	if (inject_process_env64_PATH(target_pid, target_process_libc_so_path.c_str(), p_mmap_offset, p_munmap_offset, p_getenv_offset, p_setenv_offset, add_path) != 0) {
		return ERR_INJECT_PROC64_ENV;
	}
	return ERR_NONE;
}


ssize_t safe_inject_process_env64_PATH_wrapper(const char* str_root_key, int target_pid, const char* add_path,
	api_offset_read_mode api_mode /* = api_offset_read_mode::all*/) {
	ssize_t out_err;
	std::string libc_path;
	fork_pipe_info finfo;
	out_err = ERR_NONE;
	if(fork_pipe_child_process(finfo)) {
		if (kernel_root::get_root(str_root_key) == 0) {
			libc_path = find_process_libc_so_path(target_pid);
			if (libc_path.empty()) {
				out_err = ERR_LIBC_PATH_EMPTY;
			}
		} else {
			out_err = ERR_NO_ROOT;
		}
		write_errcode_from_child(finfo, out_err);
		write_string_from_child(finfo, libc_path);
		_exit(0);
		return {};
	}
	if(!wait_fork_child_process(finfo)) {
		out_err = ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, out_err)) {
			out_err = ERR_READ_CHILD_ERRCODE;
		} else if(!read_string_from_child(finfo, libc_path)) {
			out_err = ERR_READ_CHILD_STRING;
		}
	}
	if(out_err != ERR_NONE) {
		return out_err;
	} else if(libc_path.empty()) {
		out_err = ERR_LIBC_PATH_EMPTY;
		return out_err;
	}
	ROOT_PRINTF("target_process_libc_so_path:%s\n", libc_path.c_str());


	size_t p_mmap_offset;
	size_t p_munmap_offset;
	size_t p_getenv_offset;
	size_t p_setenv_offset;
	out_err = _load_libc64_modify_env_func_addr(
		str_root_key,
		libc_path.c_str(),
		api_mode,
		p_mmap_offset,
		p_munmap_offset,
		p_getenv_offset,
		p_setenv_offset);

	if (out_err != ERR_NONE) {
		ROOT_PRINTF("_load_libc64_modify_env_func_addr error:%zd\n", out_err);
		return out_err;
	}
	ROOT_PRINTF("p_mmap_offset:%zu\n", p_mmap_offset);
	ROOT_PRINTF("p_munmap_offset:%zu\n", p_munmap_offset);
	ROOT_PRINTF("p_getenv_offset:%zu\n", p_getenv_offset);
	ROOT_PRINTF("p_setenv_offset:%zu\n", p_setenv_offset);

	if(!p_mmap_offset || !p_munmap_offset || !p_getenv_offset || !p_setenv_offset) {
		return ERR_LOAD_LIBC_FUNC_ADDR;
	}

	finfo.reset();
	out_err = ERR_NONE;
	if(fork_pipe_child_process(finfo)) {
		if (kernel_root::get_root(str_root_key) == 0) {
			out_err = inject_process_env64_PATH(target_pid, libc_path.c_str(), p_mmap_offset, p_munmap_offset, p_getenv_offset, p_setenv_offset, add_path);
		} else {
			out_err = ERR_NO_ROOT;
		}
		write_errcode_from_child(finfo, out_err);
		_exit(0);
		return {};
	}
	
	if(!wait_fork_child_process(finfo)) {
		out_err = ERR_WAIT_FORK_CHILD;
	} else {
		if(!read_errcode_from_child(finfo, out_err)) {
			out_err = ERR_READ_CHILD_ERRCODE;
		}
	}
	return out_err;
}


ssize_t kill_process(const char* str_root_key, pid_t pid) {
	ssize_t err = ERR_NONE;
	if (kernel_root::get_root(str_root_key) == 0) {
		if(kill(pid, SIGKILL) != 0) {
			err = ERR_KILL;
		}
	} else {
		err = ERR_NO_ROOT;
	}
	return err;
}

ssize_t safe_kill_process(const char* str_root_key, pid_t pid) {


	fork_pipe_info finfo;
	if(fork_pipe_child_process(finfo)) {
		ssize_t err = kill_process(str_root_key, pid);
		write_errcode_from_child(finfo, err);
		_exit(0);
		return 0;
	}
	ssize_t err = ERR_NONE;
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
