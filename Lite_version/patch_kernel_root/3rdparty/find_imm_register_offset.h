#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <sstream>
#include <regex>
#include <string>
#include <cstdint>
#include "capstone-4.0.2-win64/include/capstone/capstone.h"

namespace a64_find_imm_register_offset {
struct code_line {
	uint64_t addr;
	std::string mnemonic;
	std::string op_str;
};

uint32_t extract_imm(const std::string& op_str) {
	std::regex re("#(0x[0-9a-fA-F]+|[0-9]+)");
	std::smatch match;
	if (std::regex_search(op_str, match, re)) {
		return static_cast<uint32_t>(std::stoul(match[1], nullptr, 0));
	}
	return 0;
}

bool handle_candidate_offsets(const std::string& group_name, const std::vector<code_line>& v_code_line, std::vector<size_t> &candidate_offsets) {
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& item = v_code_line[x];
		uint32_t imm = extract_imm(item.op_str);
		candidate_offsets.push_back(imm);
	}
	return true;
}

bool is_ret_exist(const std::vector<code_line>& v_code_line) {
	for (auto x = 0; x < v_code_line.size(); x++) {
		auto& item = v_code_line[x];
		if (item.mnemonic == "ret") {
			return true;
		}
	}
	return false;
}

bool find_imm_register_offset(const std::vector<char>& file_buf, size_t start, std::vector<size_t>& candidate_offsets) {
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
	while (cs_disasm_iter(handle, &code, &file_size, &address, insn)) {
		code_line line;
		line.addr = insn->address;
		line.mnemonic = insn->mnemonic;
		line.op_str = insn->op_str;
		v_code_line.push_back(line);

		cs_detail* detail = insn->detail;
		if (detail->groups_count > 0 && v_code_line.size() >= 2) {
			if (!is_ret_exist(v_code_line)) {
				continue;
			}
			std::string group_name = cs_group_name(handle, detail->groups[0]);
			res = handle_candidate_offsets(group_name, v_code_line, candidate_offsets);
			if (res) {
				break;
			}
		}
	}
	cs_free(insn, 1);
	cs_close(&handle);
	return res;
}
}