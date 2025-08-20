COMMON_CPPFLAGS := \
	 -std=c++17 \
    -fPIC \
    -fvisibility=hidden \
	-fexceptions


PARENT_ROOT := $(LOCAL_PATH)/../../
LOCAL_CPPFLAGS     += $(COMMON_CPPFLAGS)
LOCAL_C_INCLUDES += $(PARENT_ROOT)
