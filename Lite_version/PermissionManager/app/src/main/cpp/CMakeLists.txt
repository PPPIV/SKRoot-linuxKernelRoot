# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

# Declares and names the project.

project("permissionmanager")

set(OTHER_SRC
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_command.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_exec_process.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_myinfo.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_fork_helper.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_process_cmdline_utils.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_process64_inject.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_ptrace_arm64_utils.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_su_install_helper.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_upx_helper.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_parasite_app.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/cpp/private/rootkit_parasite_patch_elf.cpp"

		"${CMAKE_CURRENT_SOURCE_DIR}/cJSON.cpp"
		"${CMAKE_CURRENT_SOURCE_DIR}/native-lib.cpp"
		)
# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
		permissionmanager

		# Sets the library as a shared library.
		SHARED

		# Provides a relative path to your source file(s).
		${OTHER_SRC})

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_include_directories(
		permissionmanager
		PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/
		${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit
		${CMAKE_CURRENT_SOURCE_DIR}/../../../../../testRoot/jni/kernel_root_kit/include
)

target_link_libraries( # Specifies the target library.
        permissionmanager

        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})