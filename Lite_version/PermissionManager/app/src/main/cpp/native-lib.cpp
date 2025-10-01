#include <jni.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sstream>
#include <thread>
#include <filesystem>
#include <sys/capability.h>

#include "kernel_root_kit/include/rootkit_umbrella.h"
#include "urlEncodeUtils.h"
#include "cJSON.h"
using namespace std;

std::string g_last_su_file_path;

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_testRoot(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    std::string result = kernel_root::get_root_test_report(strRootKey.c_str());
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_runRootCmd(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring cmd) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(cmd, 0);
    string strCmd= str1;
    env->ReleaseStringUTFChars(cmd, str1);

    string result;
    KRootErr err = kernel_root::run_root_cmd(strRootKey.c_str(), strCmd.c_str(), result);
    stringstream sstr;
    sstr << "run_root_cmd err:" << to_num(err) << ", result:" << result;
    return env->NewStringUTF(sstr.str().c_str());
}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_rootExecProcessCmd(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring cmd) {
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(cmd, 0);
    string strCmd= str1;
    env->ReleaseStringUTFChars(cmd, str1);

    KRootErr err = kernel_root::root_exec_process(strRootKey.c_str(), strCmd.c_str());

    stringstream sstr;
    sstr << "root_exec_process err:" << to_num(err);
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_installSu(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    //安装su工具套件
    std::string su_hide_full_path;
    KRootErr err = kernel_root::install_su(strRootKey.c_str(), su_hide_full_path);

    stringstream sstr;
    sstr << "install su err:" << to_num(err) <<", su_hide_full_path:" << su_hide_full_path << std::endl;
    g_last_su_file_path = su_hide_full_path;
    if (err == KRootErr::ERR_NONE) {
        sstr << "install_su done."<< std::endl;
    }
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_getLastSuFilePath(
        JNIEnv* env,
        jobject /* this */) {
    return env->NewStringUTF(g_last_su_file_path.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_uninstallSu(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    stringstream sstr;

    KRootErr err = kernel_root::uninstall_su(strRootKey.c_str());
    sstr << "uninstall_su err:" << to_num(err) << std::endl;
    if (err != KRootErr::ERR_NONE) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    g_last_su_file_path.clear();
    sstr << "uninstall_su done.";
    return env->NewStringUTF(sstr.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_autoSuEnvInject(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline) {
    
    if(g_last_su_file_path.empty()) {
        return env->NewStringUTF("【错误】请先安装部署su");
    }
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    stringstream sstr;

    //杀光所有历史进程
    std::set<pid_t> out;
    KRootErr err = kernel_root::find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), out);
    sstr << "find_all_cmdline_process err:"<< to_num(err) <<", cnt:"<<out.size() << std::endl;
    if (err != KRootErr::ERR_NONE) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    std::string kill_cmd;
    for (pid_t t : out) {
        err =  kernel_root::kill_process(strRootKey.c_str(), t);
        sstr << "kill_ret err:"<< to_num(err) << std::endl;
        if (err != KRootErr::ERR_NONE) {
            return env->NewStringUTF(sstr.str().c_str());
        }
    }
    pid_t pid;
    err = kernel_root::wait_and_find_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), 60*1000, pid);
    std::string su_dir_path = err == KRootErr::ERR_NONE ? (std::filesystem::path(g_last_su_file_path).parent_path().string() + "/") : "";
    sstr << "auto_su_env_inject("<< to_num(err) <<", " <<  su_dir_path <<")" << std::endl;
    if (err != KRootErr::ERR_NONE) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    err = kernel_root::inject_process_env64_PATH_wrapper(strRootKey.c_str(), pid, su_dir_path.c_str());
    sstr << "auto_su_env_inject ret val:" << to_num(err) << std::endl;
    if (err != KRootErr::ERR_NONE) {
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "auto_su_env_inject done.";
    return env->NewStringUTF(sstr.str().c_str());
}



extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_getAllCmdlineProcess(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey) {
    std::stringstream ss;

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    std::string strRootKey = str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    std::map<pid_t, std::string> pid_map;
    KRootErr err = kernel_root::get_all_cmdline_process(strRootKey.c_str(), pid_map);
    if (err != KRootErr::ERR_NONE) {
        ss << "get_all_cmdline_process err:"<< to_num(err) << std::endl;
        return env->NewStringUTF(ss.str().c_str());
    }
    cJSON *root = cJSON_CreateArray();
    for (auto iter = pid_map.begin(); iter != pid_map.end(); iter++ ) {
        cJSON *item = cJSON_CreateObject();
        size_t len = iter->second.length();
        size_t max_encoded_len = 3 * len + 1;
        shared_ptr<char> spData(new (std::nothrow) char[max_encoded_len], std::default_delete<char[]>());
        memset(spData.get(), 0, max_encoded_len);
        url_encode(const_cast<char*>(iter->second.c_str()), spData.get());
        cJSON_AddNumberToObject(item, "pid",  iter->first);
        cJSON_AddStringToObject(item, "name", spData.get());
        cJSON_AddItemToArray(root, item);
    }
    ss << cJSON_Print(root);
    cJSON_Delete(root);
    return env->NewStringUTF(ss.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_parasitePrecheckApp(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline) {

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    stringstream sstr;
    std::set<pid_t> test_pid;
    KRootErr err = kernel_root::find_all_cmdline_process(strRootKey.c_str(), strTargetProcessCmdline.c_str(), test_pid);
    if (err != KRootErr::ERR_NONE) {
        sstr << "find_all_cmdline_process err:"<< to_num(err) <<", cnt:"<< test_pid.size() << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    if (test_pid.size() == 0) {
        sstr << "目标进程不存在" << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }

    std::map<std::string, kernel_root::app_dynlib_status> dynlib_path_list;
    err = kernel_root::parasite_precheck_app(strRootKey.c_str(), strTargetProcessCmdline.c_str(), dynlib_path_list);
    if (err != KRootErr::ERR_NONE) {
        sstr << "parasite_precheck_app ret val:" << to_num(err) << std::endl;
        if(err == KRootErr::ERR_EXIST_32BIT) {
            sstr << "此目标APP为32位应用，无法寄生" << to_num(err) << std::endl;
        }
        return env->NewStringUTF(sstr.str().c_str());
    }

    if (!dynlib_path_list.size()) {
        sstr << "无法检测到目标APP的JNI环境，目标APP暂不可被寄生；您可重新运行目标APP后重试；或将APP进行手动加固(加壳)，因为加固(加壳)APP后，APP会被产生JNI环境，方可寄生！" << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }

    cJSON *root = cJSON_CreateArray();
    for (auto iter = dynlib_path_list.begin(); iter != dynlib_path_list.end(); iter++) {
        cJSON *item = cJSON_CreateObject();
        size_t len = iter->first.length();
        size_t max_encoded_len = 3 * len + 1;
        std::shared_ptr<char> spData(new (std::nothrow) char[max_encoded_len], std::default_delete<char[]>());
        memset(spData.get(), 0, max_encoded_len);
        url_encode(const_cast<char*>(iter->first.c_str()), spData.get());
        cJSON_AddStringToObject(item, "name", spData.get());
        cJSON_AddNumberToObject(item, "status",  iter->second);
        cJSON_AddItemToArray(root, item);
    }
    sstr << cJSON_Print(root);
    cJSON_Delete(root);
    return env->NewStringUTF(sstr.str().c_str());

}

extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_parasiteImplantApp(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline,
        jstring targetSoFullPath) {
    stringstream sstr;
    KRootErr err;
    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    str1 = env->GetStringUTFChars(targetSoFullPath, 0);
    string strTargetSoFullPath = str1;
    env->ReleaseStringUTFChars(targetSoFullPath, str1);

    err = kernel_root::parasite_implant_app(strRootKey.c_str(), strTargetProcessCmdline.c_str(), strTargetSoFullPath.c_str());
    if (err != KRootErr::ERR_NONE) {
        sstr << "parasite_implant_app err:"<< to_num(err) << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "parasite_implant_app done.";
    return env->NewStringUTF(sstr.str().c_str());

}


extern "C" JNIEXPORT jstring JNICALL
Java_com_linux_permissionmanager_MainActivity_parasiteImplantSuEnv(
        JNIEnv* env,
        jobject /* this */,
        jstring rootKey,
        jstring targetProcessCmdline,
        jstring targetSoFullPath) {
    if(g_last_su_file_path.empty()) {
        return env->NewStringUTF("【错误】请先安装部署su");
    }

    const char *str1 = env->GetStringUTFChars(rootKey, 0);
    string strRootKey= str1;
    env->ReleaseStringUTFChars(rootKey, str1);

    str1 = env->GetStringUTFChars(targetProcessCmdline, 0);
    string strTargetProcessCmdline = str1;
    env->ReleaseStringUTFChars(targetProcessCmdline, str1);

    str1 = env->GetStringUTFChars(targetSoFullPath, 0);
    string strTargetSoFullPath = str1;
    env->ReleaseStringUTFChars(targetSoFullPath, str1);

    std::string su_dir_path = std::filesystem::path(g_last_su_file_path).parent_path().string() + "/";

    stringstream sstr;
    KRootErr err = kernel_root::parasite_implant_su_env(strRootKey.c_str(), strTargetProcessCmdline.c_str(), strTargetSoFullPath.c_str(), su_dir_path.c_str());
    if (err != KRootErr::ERR_NONE) {
        sstr << "parasite_implant_su_env err:" << to_num(err) << std::endl;
        return env->NewStringUTF(sstr.str().c_str());
    }
    sstr << "parasite_implant_su_env done.";
    return env->NewStringUTF(sstr.str().c_str());

}

