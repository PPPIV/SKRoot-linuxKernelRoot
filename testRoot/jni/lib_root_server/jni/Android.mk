LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_root_server
LOCAL_CPPFLAGS += \
    -std=c++17 \
    -fPIC \
    -fvisibility=hidden \
    -fexceptions \
    -DLIB_ROOT_SERVER_MODE
LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/../../
LOCAL_SRC_FILES := \
../lib_root_server.cpp \
../../kernel_root_kit/core/rootkit_command.cpp \
../../kernel_root_kit/core/rootkit_exec_process.cpp \
../../kernel_root_kit/core/rootkit_process_cmdline.cpp \
../../kernel_root_kit/core/rootkit_process64_inject.cpp \
../../kernel_root_kit/core/rootkit_ptrace_arm64_utils.cpp \
../../kernel_root_kit/core/rootkit_su_install_helper.cpp \
../../kernel_root_kit/core/rootkit_upx_helper.cpp \
../../kernel_root_kit/core/rootkit_parasite_app.cpp \
../../kernel_root_kit/core/rootkit_parasite_patch_elf.cpp \
../../utils/cJSON.cpp
include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
