LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := testRoot
LOCAL_SRC_FILES := testRoot.cpp

KERNEL_ROOT_KIT := $(LOCAL_PATH)/kernel_root_kit
include $(KERNEL_ROOT_KIT)/Android.mk
include $(LOCAL_PATH)/build_macros.mk
include $(BUILD_EXECUTABLE)
