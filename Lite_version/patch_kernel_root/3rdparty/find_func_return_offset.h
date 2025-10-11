#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <sstream>
#include <regex>
#include <string>
#include <cstdint>
#include <algorithm>
#include "capstone-4.0.2-win64/include/capstone/capstone.h"

namespace a64_find_func_return_offset {
	constexpr size_t k_npos = static_cast<size_t>(-1);
	constexpr int k_max_jump_region = 1024 * 1024; // 1MB
	struct code_line {
		uint64_t addr = 0;
		arm64_insn cmd_id = ARM64_INS_INVALID;
		arm64_cc cc_id = ARM64_CC_INVALID;
		int64_t final_imm = 0;
	};

	bool is_offset_jump_asm(const code_line& line) {
		return line.cmd_id == ARM64_INS_B;
	}
	
	bool is_force_jump_asm(const code_line& line) {
		return line.cmd_id == ARM64_INS_B && (line.cc_id == ARM64_CC_INVALID || line.cc_id == ARM64_CC_AL || line.cc_id == ARM64_CC_NV);
		return line.cmd_id == ARM64_INS_BR;
	}

	size_t get_aarch64_ret_count(const std::vector<char>& file_buf, const std::vector<code_line>& v) {
		size_t cnt = 0;
		for (auto& line : v) {
			if (line.cmd_id == ARM64_INS_RET) cnt++;
		}
		return cnt;
	}
	static size_t index_by_addr(const std::vector<code_line>& v, uint64_t addr) {
		auto it = std::lower_bound(
			v.begin(), v.end(), addr,
			[](const code_line& L, uint64_t a) { return L.addr < a; });
		if (it != v.end() && it->addr == addr) return static_cast<size_t>(it - v.begin());
		return k_npos;
	}

	static void scan_from_index(const std::vector<code_line>& v_code_line,
		size_t start_idx,
		std::set<uint64_t>& branch_history,
		std::vector<uint64_t>& out_ret_addrs,
		std::vector<uint64_t>& out_branch_anchors) {
		for (size_t x = start_idx; x < v_code_line.size(); ++x) {
			const auto& line = v_code_line[x];
			if (is_offset_jump_asm(line)) {
				const int64_t addr = line.final_imm;
				if (addr > 0 && addr < (line.addr + k_max_jump_region)) {
					const uint64_t fork = static_cast<uint64_t>(addr);
					if (!branch_history.count(fork)) {
						branch_history.insert(fork);
						out_branch_anchors.push_back(fork);
					}
				}
				if (is_force_jump_asm(line)) break;   // force jump, there stop.
				continue;
			}
			if (line.cmd_id == ARM64_INS_RET) {
				out_ret_addrs.push_back(line.addr);
			}
		}
	}

	bool handle_candidate_offsets(const std::vector<code_line>& v_code_line, size_t& candidate_offsets) {
		std::vector<uint64_t> ret_addrs;
		std::vector<uint64_t> branch_anchors;
		std::set<uint64_t> branch_history;

		// scane main line
		scan_from_index(v_code_line, 0, branch_history, ret_addrs, branch_anchors);

		// scane second line
		while (!branch_anchors.empty()) {
			const uint64_t fork_addr = branch_anchors.back();
			branch_anchors.pop_back();

			const size_t idx = index_by_addr(v_code_line, fork_addr);
			if (idx == k_npos) {
				return false;  // need more code line
			}

			scan_from_index(v_code_line, idx, branch_history, ret_addrs, branch_anchors);
		}

		if (!ret_addrs.empty()) {
			candidate_offsets = *std::max_element(ret_addrs.begin(), ret_addrs.end());
			return true;
		}
		return false;
	}

	bool find_func_return_offset(const std::vector<char>& file_buf, size_t start, size_t& candidate_offsets) {
		bool res = false;
		csh handle;
		cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			abort();
		}
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
		//cs_option(handle, CS_OPT_UNSIGNED, CS_OPT_ON);

		cs_insn* insn = cs_malloc(handle);
		uint64_t address = 0x0;
		const uint8_t* code = (const uint8_t*)&file_buf[0] + start;
		size_t file_size = file_buf.size() - start;
		std::vector<code_line> v_code_line;
		v_code_line.reserve(100);
		size_t last_ret_cnt = 0;
		while (cs_disasm_iter(handle, &code, &file_size, &address, insn)) {
			code_line line;
			line.addr = insn->address;
			line.cmd_id = (arm64_insn)insn->id;
			line.cc_id = insn->detail->arm64.cc;
			for (auto y = 0; y < insn->detail->arm64.op_count; y++) {
				if (insn->detail->arm64.operands[y].type == ARM64_OP_IMM) {
					auto imm = insn->detail->arm64.operands[y].imm;
					if(imm > 0) line.final_imm = imm;
				}
			}
			v_code_line.push_back(line);

			size_t ret_cnt = get_aarch64_ret_count(file_buf, v_code_line);
			if (ret_cnt == last_ret_cnt) continue;
			last_ret_cnt = ret_cnt;
			res = handle_candidate_offsets(v_code_line, candidate_offsets);
			if (res) break;
			if (v_code_line.size() > 0x10000) break; //error
		}
		cs_free(insn, 1);
		cs_close(&handle);
		return res;
	}
}