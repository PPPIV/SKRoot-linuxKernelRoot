LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := kernel_root_kit_static

LOCAL_PIC := true

KERNEL_ROOT_KIT := $(LOCAL_PATH)/../../../kernel_root_kit

LIB_ROOT_SERVER_DATA_FILE  := $(KERNEL_ROOT_KIT)/src/jni/lib_root_server/lib_root_server_data.h
ifneq ($(wildcard $(LIB_ROOT_SERVER_DATA_FILE)),)
  LOCAL_CPPFLAGS += -include $(LIB_ROOT_SERVER_DATA_FILE)
endif

SU_EXEC_DATA_FILE  := $(KERNEL_ROOT_KIT)/src/jni/su/su_exec_data.h
ifneq ($(wildcard $(SU_EXEC_DATA_FILE)),)
  LOCAL_CPPFLAGS += -include $(SU_EXEC_DATA_FILE)
endif

include $(KERNEL_ROOT_KIT)/src/jni/rootkit_src_file.mk
include $(LOCAL_PATH)/build_macros_static.mk

include $(BUILD_STATIC_LIBRARY)