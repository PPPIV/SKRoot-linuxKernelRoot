KERNEL_ROOT_KIT_SRCS := \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_command.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_myinfo.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_exec_process.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_fork_helper.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_parasite_app.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_parasite_patch_elf.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_process_cmdline_utils.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_process64_inject.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_ptrace_arm64_utils.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_su_hide_folder.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_su_install_helper.cpp \
    $(KERNEL_ROOT_KIT)/cpp/private/rootkit_upx_helper.cpp
LOCAL_SRC_FILES += $(KERNEL_ROOT_KIT_SRCS)
LOCAL_C_INCLUDES += $(KERNEL_ROOT_KIT)
LOCAL_C_INCLUDES += $(KERNEL_ROOT_KIT)/include
