@echo off
cd /d "%~dp0"

set "work_path=%~dp0"
set "kernel_root_path=%~dp0../kernel_root_kit/cpp/private"

echo %work_path%
echo %kernel_root_path%

if not exist %work_path%libs/arm64-v8a/lib_root_server.so (
    echo Error: '%work_path%libs/arm64-v8a/lib_root_server.so' does not exist!
    pause
    exit /b
)

:: 使用 echo 和管道(|) 来模拟按下回车键的操作
echo.|"%kernel_root_path%/file_convert_to_source_tools/file_convert_to_source_tools.exe" %work_path%/libs/arm64-v8a/lib_root_server.so

:: 确保上面的命令执行成功，再进行以下的文件替换操作
if %errorlevel% neq 0 (
    echo Error: 'file_convert_to_source_tools.exe' execution failed!
    pause
    exit /b
)

:: 将res.h文件中的文本进行替换
powershell -Command "(Get-Content res.h) -replace 'namespace {', 'namespace kernel_root {' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'fileSize', 'lib_root_server_file_size' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'data', 'lib_root_server_file_data' | Set-Content res.h"

:: 将临时文件重命名为最终的文件名
move /Y res.h rootkit_lib_root_server_data.h

if exist res.h (
    del res.h
)

if exist "%work_path%\libs" (
    rmdir /S /Q "%work_path%\libs"
)

if exist "%work_path%\obj" (
    rmdir /S /Q "%work_path%\obj"
)

echo Finished generating the 'rootkit_lib_root_server_data.h' file!
move /Y rootkit_lib_root_server_data.h %kernel_root_path%
echo Successfully moved file 'rootkit_lib_root_server_data.h'!
