@echo off
set "ndk_path=c:\Users\abc\android-ndk-r25\ndk-build.cmd"

cd /d "%~dp0"

set "root_path=%~dp0"

cd %root_path%
call Clean.bat

if not exist %ndk_path% (
    echo Error:  Android NDK: '%ndk_path%' does not exist!
    pause
    exit /b
)

call "%ndk_path%" clean

cd %root_path%\su\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %root_path%\su
call generate_source_su_exec_data.bat

cd %root_path%\lib_su_env\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %root_path%\lib_su_env
call generate_source_lib_su_env_data.bat

cd %root_path%\3rdparty\upx
call generate_source_upx_data.bat

cd %root_path%\lib_root_server
call generate_source_lib_root_server_html_data.bat
cd %root_path%\lib_root_server\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %root_path%\lib_root_server
call generate_source_lib_root_server_data.bat

cd %root_path%
call "%ndk_path%"

echo All builds completed!
pause
