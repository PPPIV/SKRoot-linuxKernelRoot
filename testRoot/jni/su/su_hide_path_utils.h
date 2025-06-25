#pragma once
#include <dirent.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <filesystem>
#include "su_encryptor.h"

#define RANDOM_GUID_LEN 4
#define ROOT_KEY_LEN 48
#define ENCRYKEY "ECC08B04-B9FF-40B5-9596-4408626181D5"

namespace kernel_root{
namespace su{
    /*
 * xattr name for SELinux attributes.
 * This may have been exported via Kernel uapi header.
 */
#ifndef XATTR_NAME_SELINUX
#define XATTR_NAME_SELINUX "security.selinux"
#endif

#ifndef SELINUX_FILE_FLAG
#define SELINUX_FILE_FLAG "u:object_r:system_file:s0"
#endif

static bool set_file_allow_access_mode(const std::string & file_full_path) {
    if (chmod(file_full_path.c_str(), 0777)) {
        return false;
    }
    if (setxattr(file_full_path.c_str(), XATTR_NAME_SELINUX, SELINUX_FILE_FLAG, strlen(SELINUX_FILE_FLAG) + 1, 0)) {
        return false;
    }
    return true;
}


static std::string __internal_find_su_hide_folder_path(
		int deep,
		const char* base_path) {
	std::string folder;
	DIR* dir;
	struct dirent* entry;

	dir = opendir(base_path);
	if (dir == NULL)
		return {};

	while ((entry = readdir(dir)) != NULL) {
		if ((strcmp(entry->d_name, ".") == 0) ||
			(strcmp(entry->d_name, "..") == 0)) {
			continue;
		} else if (entry->d_type != DT_DIR) {
            if (strcmp(entry->d_name, "su") == 0) {
                folder = base_path;
                break;
            }
			continue;
		}
		std::string next_path = base_path;
		next_path += "/";
		next_path += entry->d_name;
		std::string next_found = __internal_find_su_hide_folder_path(deep + 1, next_path.c_str());
		if(!next_found.empty()) {
			folder = next_found;
			break;
		}
	}
	closedir(dir);
	return folder;
}

static std::string find_su_hide_folder_path(const char* str_root_key, const char* base_path) {
	std::string before16 = std::string(str_root_key).substr(0, 16);
	std::string file_path = base_path;
	file_path += "/" + before16;
	return __internal_find_su_hide_folder_path(0, file_path.c_str());
}

static bool __create_directory_if_not_exists(const std::string& dir_path) {
    if (access(dir_path.c_str(), F_OK) == -1) {
        return mkdir(dir_path.c_str(), 0755) == 0;
    }
    return true;
}

static std::string create_su_hide_folder(const char* str_root_key, const char* base_path) {
    std::string before16 = std::string(str_root_key).substr(0, 16);

    char guid[RANDOM_GUID_LEN] = {0};
    rand_str(guid, sizeof(guid));
    std::string encodeRootKey(guid, sizeof(guid));
    encodeRootKey += str_root_key;

	encodeRootKey = encryp_string(encodeRootKey, ENCRYKEY);

    std::string file_path = base_path;
    file_path += "/" + before16;
    // Check and create directories
    if (!__create_directory_if_not_exists(file_path)) return {};
    if (!set_file_allow_access_mode(file_path)) return {};

    file_path += "/_" + encodeRootKey;
    if (!__create_directory_if_not_exists(file_path)) return {};
    if (!set_file_allow_access_mode(file_path)) return {};

    return file_path + "/";
}

static bool del_su_hide_folder(const char* str_root_key,
										 const char* base_path) {

	std::string before16 = std::string(str_root_key).substr(0, 16);
	std::string file_path = base_path;
	file_path += "/" + before16;
	try {
		std::filesystem::remove_all(file_path);
	} catch (...) {
	}
	return std::filesystem::exists(file_path);
}

static inline std::string parse_root_key_by_su_path(
	const char* su_path) {
	std::string path = su_path;
	if (path.empty()) {
		return {};
	}
	int n = path.find_last_of("_");
	if (n == -1) {
		return {};
	}
	path = path.substr(++n);
	n = path.find("/");
	if (n != -1) {
		path.substr(0, n);
	}

	std::string decodeRootKey = uncryp_string(path, ENCRYKEY);

	if (decodeRootKey.length() < (RANDOM_GUID_LEN + ROOT_KEY_LEN)) {
		return {};
	}
	return decodeRootKey.substr(decodeRootKey.length() - ROOT_KEY_LEN);
}
}
}
