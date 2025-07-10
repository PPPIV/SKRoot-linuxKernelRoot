LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS += -std=c++20 -fPIE -fvisibility=hidden -fexceptions
LOCAL_LDFLAGS += -fPIE -pie
LOCAL_DISABLE_FATAL_LINKER_WARNINGS := true
LOCAL_MODULE := testRoot
LOCAL_SRC_FILES := testRoot.cpp

include $(LOCAL_PATH)/kernel_root_kit.mk
include $(BUILD_EXECUTABLE)
