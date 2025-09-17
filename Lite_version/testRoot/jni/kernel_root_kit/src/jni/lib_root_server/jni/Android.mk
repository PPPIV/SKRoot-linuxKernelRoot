LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := lib_root_server
LOCAL_SRC_FILES := \
../lib_root_server.cpp \
../utils/cJSON.cpp

KERNEL_ROOT_KIT := $(LOCAL_PATH)/../../../../../kernel_root_kit
LOCAL_C_INCLUDES  += $(KERNEL_ROOT_KIT)/include
LOCAL_LDFLAGS  += $(KERNEL_ROOT_KIT)/lib/libkernel_root_kit_static.a

include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
