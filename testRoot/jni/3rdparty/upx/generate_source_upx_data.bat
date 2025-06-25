@echo off
cd /d "%~dp0"

set "work_path=%~dp0"
set "kernel_root_path=%~dp0../../kernel_root_kit/core"

echo %work_path%
echo %kernel_root_path%

if not exist %work_path%upx-5.0.1-arm64_linux/upx (
    echo Error: '%work_path%upx-5.0.1-arm64_linux/upx' does not exist!
    pause
    exit /b
)

:: 使用 echo 和管道(|) 来模拟按下回车键的操作
echo.|"%kernel_root_path%/file_convert_to_source_tools/file_convert_to_source_tools.exe" %work_path%upx-5.0.1-arm64_linux/upx

:: 确保上面的命令执行成功，再进行以下的文件替换操作
if %errorlevel% neq 0 (
    echo Error: 'file_convert_to_source_tools.exe' execution failed!
    pause
    exit /b
)

:: 将res.h文件中的文本进行替换
powershell -Command "(Get-Content res.h) -replace 'namespace {', 'namespace kernel_root {' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'fileSize', 'upx_file_size' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'data', 'upx_file_data' | Set-Content res.h"

move /Y res.h rootkit_upx_data.h

if exist res.h (
    del res.h
)

echo Finished generating the 'rootkit_upx_data.h' file!
move /Y rootkit_upx_data.h %kernel_root_path%
echo Successfully moved file 'rootkit_upx_data.h'!
