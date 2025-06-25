LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++17 -fPIE -fvisibility=hidden -fexceptions
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE := testRoot
LOCAL_SRC_FILES := \
testRoot.cpp \
kernel_root_kit/core/rootkit_command.cpp \
kernel_root_kit/core/rootkit_exec_process.cpp \
kernel_root_kit/core/rootkit_process_cmdline.cpp \
kernel_root_kit/core/rootkit_process64_inject.cpp \
kernel_root_kit/core/rootkit_ptrace_arm64_utils.cpp \
kernel_root_kit/core/rootkit_su_install_helper.cpp \
kernel_root_kit/core/rootkit_parasite_app.cpp \
kernel_root_kit/core/rootkit_parasite_patch_elf.cpp \
kernel_root_kit/core/rootkit_upx_helper.cpp
include $(BUILD_EXECUTABLE)
