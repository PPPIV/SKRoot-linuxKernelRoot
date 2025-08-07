LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_su_env
LOCAL_C_INCLUDES += \
    $(LOCAL_PATH)/../../
LOCAL_CPPFLAGS += -std=c++17 -fPIC -fvisibility=hidden -fexceptions
LOCAL_SRC_FILES := ../lib_su_env.cpp
include $(BUILD_SHARED_LIBRARY)