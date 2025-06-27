#pragma once
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <math.h>
#define ROOT_KEY_LEN 48

static const char HEX[16] = {
'0', '1', '2', '3',
'4', '5', '6', '7',
'8', '9', 'a', 'b',
'c', 'd', 'e', 'f'
};

static std::vector<char> read_file_buf(const std::string& file_path) {
	std::ifstream file(file_path, std::ios::binary | std::ios::ate);
	if (file) {
		auto size = file.tellg();
		std::vector<char> buffer(size);
		file.seekg(0, std::ios::beg);
		file.read(buffer.data(), size);
		file.close();
		return buffer;
	}
	return {};
}

static void get_rand_str(char* dest, int n) {
	int i, randno;
	char stardstring[63] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	srand((unsigned)time(NULL));
	for (i = 0; i < n; i++) {
		randno = rand() % 62;
		*dest = stardstring[randno];
		dest++;
	}
}

static std::string generate_random_root_key() {
	char root_key_data[ROOT_KEY_LEN] = { 0 };
	get_rand_str(root_key_data, sizeof(root_key_data));
	std::string str_root_key(root_key_data, sizeof(root_key_data));
	return str_root_key;
}

static auto hex2bytes(uint8_t* hex, uint8_t* str) -> void {
	char high, low;
	for (size_t i = 0, length = strlen((char*)hex); i < length; i += 2) {
		high = toupper(hex[i]) - '0';
		low = toupper(hex[i + 1]) - '0';
		str[i / 2] = ((high > 9 ? high - 7 : high) << 4) + (low > 9 ? low - 7 : low);
	}
}
static std::string bytes2hex(const unsigned char* input, size_t length) {

	std::string str;
	str.reserve(length << 1);
	for (size_t i = 0; i < length; ++i) {
		int t = input[i];
		int a = t / 16;
		int b = t % 16;
		str.append(1, HEX[a]);
		str.append(1, HEX[b]);
	}
	return str;
}

static bool write_file_bytes(const char* file_path, size_t offset, const char* bytes, size_t len) {
	std::fstream file_stream(file_path, std::ios::in | std::ios::out | std::ios::binary);
	if (!file_stream) {
		return false;
	}
	file_stream.seekp(offset);
	if (!file_stream.good()) {
		file_stream.close();
		return false;
	}
	file_stream.write(bytes, len);
	if (!file_stream.good()) {
		file_stream.close();
		return false;
	}
	file_stream.close();
	return true;
}

static size_t align8(size_t addr) {
	if (addr % 8 != 0) {
		addr = (addr + 7) & ~static_cast<size_t>(7);  // Align to next 8-byte boundary
	}
	return addr;
}

static size_t count_endl(const std::string& s) {
	return std::count(s.begin(), s.end(), '\n');
}

static void replace_all_distinct(std::string& str, const std::string& old_value, const std::string& new_value) {
	for (std::string::size_type pos(0); pos != std::string::npos; pos += new_value.length()) {
		if ((pos = str.find(old_value, pos)) != std::string::npos) {
			str.replace(pos, old_value.length(), new_value);
		}
		else {
			break;
		}
	}
}

static std::vector<std::string> splite_lines(const std::string& s) {
	std::vector<std::string> lines;
	std::istringstream iss(s);
	std::string line;
	while (std::getline(iss, line)) {
		if (!line.empty() && line.back() == '\r')
			line.pop_back();
		lines.push_back(line);
	}
	return lines;
}