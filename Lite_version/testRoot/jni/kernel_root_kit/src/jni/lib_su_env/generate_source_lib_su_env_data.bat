@echo off
cd /d "%~dp0"

set "work_path=%~dp0"
set "kernel_root_path=%~dp0../../../../kernel_root_kit/src/jni"

echo %work_path%
echo %kernel_root_path%

if not exist %work_path%libs/arm64-v8a/lib_su_env.so (
    echo Error: '%work_path%libs/arm64-v8a/lib_su_env.so' does not exist!
    pause
    exit /b
)

:: 使用 echo 和管道(|) 来模拟按下回车键的操作
echo.|"%kernel_root_path%/file_convert_to_source_tools/file_convert_to_source_tools.exe" %work_path%/libs/arm64-v8a/lib_su_env.so

:: 确保上面的命令执行成功，再进行以下的文件替换操作
if %errorlevel% neq 0 (
    echo Error: 'file_convert_to_source_tools.exe' execution failed!
    pause
    exit /b
)

:: 将res.h文件中的文本进行替换
powershell -Command "(Get-Content res.h) -replace 'namespace {', 'namespace kernel_root {' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'fileSize', 'lib_su_env_file_size' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'data', 'lib_su_env_file_data' | Set-Content res.h"

move /Y res.h lib_su_env_data.h


if exist res.h (
    del res.h
)

if exist "%work_path%\libs" (
    rmdir /S /Q "%work_path%\libs"
)

if exist "%work_path%\obj" (
    rmdir /S /Q "%work_path%\obj"
)

echo Finished generating the 'lib_su_env_data.h' file!