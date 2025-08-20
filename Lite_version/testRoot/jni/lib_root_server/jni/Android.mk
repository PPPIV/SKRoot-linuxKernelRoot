LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_root_server
LOCAL_CPPFLAGS += -DLIB_ROOT_SERVER_MODE
LOCAL_SRC_FILES := \
../lib_root_server.cpp \
../../utils/cJSON.cpp

KERNEL_ROOT_KIT := $(LOCAL_PATH)/../../kernel_root_kit
include $(KERNEL_ROOT_KIT)/Android.mk
include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
