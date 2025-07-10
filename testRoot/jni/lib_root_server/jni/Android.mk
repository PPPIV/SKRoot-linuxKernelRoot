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
../../utils/cJSON.cpp

include $(LOCAL_PATH)/kernel_root_kit.mk
include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
