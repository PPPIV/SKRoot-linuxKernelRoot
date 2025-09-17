@echo off
cd /d "%~dp0"

set "work_path=%~dp0"
set "kernel_root_path=%~dp0../../../../kernel_root_kit/src/jni"

echo %work_path%
echo %kernel_root_path%

if not exist %work_path%libs/arm64-v8a/su (
    echo Error: '%work_path%libs/arm64-v8a/su' does not exist!
    pause
    exit /b
)

:: 使用 echo 和管道(|) 来模拟按下回车键的操作
echo.|"%kernel_root_path%/file_convert_to_source_tools/file_convert_to_source_tools.exe" %work_path%/libs/arm64-v8a/su

:: 确保上面的命令执行成功，再进行以下的文件替换操作
if %errorlevel% neq 0 (
    echo Error: 'file_convert_to_source_tools.exe' execution failed!
    pause
    exit /b
)

:: 将res.h文件中的文本进行替换
powershell -Command "(Get-Content res.h) -replace 'namespace {', 'namespace kernel_root {' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'fileSize', 'su_exec_file_size' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'data', 'su_exec_data' | Set-Content res.h"

powershell -NoProfile -Command "$ins='#endif'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#define SU_EXEC_DATA 1'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#ifndef SU_EXEC_DATA'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#include <stdint.h>'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#pragma once'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"


:: 将临时文件重命名为最终的文件名
move /Y res.h su_exec_data.h

if exist res.h (
    del res.h
)

if exist "%work_path%\libs" (
    rmdir /S /Q "%work_path%\libs"
)

if exist "%work_path%\obj" (
    rmdir /S /Q "%work_path%\obj"
)

echo Finished generating the 'su_exec_data.h' file!

