#pragma once
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <map>
#include <set>
#include <vector>

#include "rootkit_err_def.h"

namespace kernel_root {
class fork_base_info {
public:
	fork_base_info() { reset(); }
	~fork_base_info() { close(); }
	void reset() {
		close();
		fd_read_parent = -1;
		fd_write_parent = -1;
		fd_read_child = -1;
		fd_write_child = -1;
		parent_pid = getpid();
		child_pid = 0;
	}

	void close() {
		if (fd_read_parent != -1) {
			::close(fd_read_parent);
			fd_read_parent = -1;
		}
		if (fd_write_parent != -1) {
			::close(fd_write_parent);
			fd_write_parent = -1;
		}
		if (fd_read_child != -1) {
			::close(fd_read_child);
			fd_read_child = -1;
		}
		if (fd_write_child != -1) {
			::close(fd_write_child);
			fd_write_child = -1;
		}
	}
	int fd_read_parent = -1;
    int fd_write_parent = -1;
    int fd_read_child = -1;
    int fd_write_child = -1;
    int parent_pid = -1;
    int child_pid = -1;
};
class fork_pipe_info : public fork_base_info {};

bool fork_pipe_child_process(fork_pipe_info & finfo);

bool is_fork_child_process_work_finished(const fork_base_info & finfo);

bool write_transfer_data_from_child(const fork_pipe_info & finfo, void* data, size_t data_len);

bool read_transfer_data_from_child(fork_pipe_info & finfo, std::vector<uint8_t>& out);

bool write_errcode_from_child(const fork_pipe_info & finfo, KRootErr errCode);

bool read_errcode_from_child(const fork_pipe_info & finfo, KRootErr & errCode);

bool write_int_from_child(const fork_pipe_info & finfo, int n);

bool read_int_from_child(const fork_pipe_info & finfo, int & n);

bool write_uint64_from_child(const fork_pipe_info & finfo, uint64_t n);

bool read_uint64_from_child(const fork_pipe_info & finfo, uint64_t & n);

bool write_set_int_from_child(const fork_pipe_info & finfo, const std::set<int> & s);

bool read_set_int_from_child(fork_pipe_info & finfo, std::set<int> & s);

bool write_string_from_child(const fork_pipe_info & finfo, const std::string &text);

bool read_string_from_child(fork_pipe_info & finfo, std::string &text);

bool write_set_string_from_child(const fork_pipe_info & finfo, const std::set<std::string> &s);

bool read_set_string_from_child(fork_pipe_info &finfo, std::set<std::string> &s);

bool write_map_i_s_from_child(const fork_pipe_info & finfo, const std::map<int, std::string> & map);

bool read_map_i_s_from_child(fork_pipe_info & finfo, std::map<int, std::string> & map);

bool write_map_s_i_from_child(const fork_pipe_info & finfo, const std::map<std::string, int> & map);

bool read_map_s_i_from_child(fork_pipe_info & finfo, std::map<std::string, int> & map);

}
