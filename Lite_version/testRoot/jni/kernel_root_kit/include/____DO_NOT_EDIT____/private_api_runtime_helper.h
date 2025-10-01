#pragma once
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../rootkit_err_def.h"
#include "../rootkit_parasite_app_dynlib_status.h"
namespace kernel_root {

static thread_local std::string* g_output_su_path = nullptr;
static void su_path_cb(const char* su_full_path) {
    if (!g_output_su_path || !su_full_path) return;
    (*g_output_su_path) = su_full_path;
}

inline KRootErr install_su(const char* str_root_key, std::string & out_su_full_path) {
    out_su_full_path.clear();
    g_output_su_path = &out_su_full_path;

    KRootErr install_su_with_cb(const char* str_root_key, void (*cb)(const char* su_full_path));
    KRootErr err = install_su_with_cb(str_root_key, su_path_cb);
    g_output_su_path = nullptr;
    return err;
}

static thread_local std::string* g_output_run_cmd_result = nullptr;
static void run_cmd_cb(const char* result) {
    if (!g_output_run_cmd_result || !result) return;
    (*g_output_run_cmd_result) = result;
}

inline KRootErr run_root_cmd(const char* str_root_key, const char* cmd, std::string & out_result) {

    out_result.clear();
    g_output_run_cmd_result = &out_result;

    KRootErr run_root_cmd_with_cb(const char* str_root_key, const char* cmd, void (*cb)(const char* result));
    KRootErr err = run_root_cmd_with_cb(str_root_key, cmd, run_cmd_cb);
    g_output_run_cmd_result = nullptr;
    return err;

}

static thread_local std::map<std::string, kernel_root::app_dynlib_status>* g_output_map = nullptr;
static void collect_cb(const char* dynlib_full_path, kernel_root::app_dynlib_status status) {
    if (!g_output_map || !dynlib_full_path) return;
    (*g_output_map)[std::string(dynlib_full_path)] = status;
}

inline KRootErr parasite_precheck_app(const char* str_root_key, const char* target_pid_cmdline, std::map<std::string, kernel_root::app_dynlib_status> &output_dynlib_full_path) {
    output_dynlib_full_path.clear();
    g_output_map = &output_dynlib_full_path;

    KRootErr parasite_precheck_app_with_cb(const char* str_root_key, const char* target_pid_cmdline, void (*cb)(const char* so_full_path, kernel_root::app_dynlib_status status));
    KRootErr err = parasite_precheck_app_with_cb(str_root_key, target_pid_cmdline, collect_cb);
    g_output_map = nullptr;
    return err;
}

static thread_local std::set<pid_t>* g_find_pid_set = nullptr;
static void find_pid_cb(pid_t pid) {
    if (!g_find_pid_set || !pid) return;
    g_find_pid_set->insert(pid);
}

inline KRootErr find_all_cmdline_process(const char* str_root_key, const char* target_cmdline, std::set<pid_t> & out, bool compare_full_agrc) {
    out.clear();
    g_find_pid_set = &out;
    KRootErr find_all_cmdline_process_with_cb(const char* str_root_key, const char* target_cmdline, void (*cb)(pid_t pid), bool compare_full_agrc);
    KRootErr err = find_all_cmdline_process_with_cb(str_root_key, target_cmdline, find_pid_cb, compare_full_agrc);
    g_find_pid_set = nullptr;
    return err;
}


static thread_local std::map<pid_t, std::string>* g_get_pidmap = nullptr;
static void get_pid_cb(pid_t pid, const char* cmdline) {
    if (!g_get_pidmap || !pid || !cmdline) return;
    (*g_get_pidmap)[pid] = cmdline;
}


inline KRootErr get_all_cmdline_process(const char* str_root_key, std::map<pid_t, std::string> & pid_map, bool compare_full_agrc) {
    pid_map.clear();
    g_get_pidmap = &pid_map;
    KRootErr get_all_cmdline_process_with_cb(const char* str_root_key, void (*cb)(pid_t pid, const char* cmdline), bool compare_full_agrc);
    KRootErr err = get_all_cmdline_process_with_cb(str_root_key, get_pid_cb, compare_full_agrc);
    g_get_pidmap = nullptr;
    return err;
}

}