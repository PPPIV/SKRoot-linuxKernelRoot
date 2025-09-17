@echo off
cd /d "%~dp0"

set "root_path=%~dp0"

if exist "%root_path%src\jni\lib_root_server\lib_root_server_data.h" (
    del "%root_path%src\jni\lib_root_server\lib_root_server_data.h"
)

if exist "%root_path%src\jni\su\su_exec_data.h" (
    del "%root_path%src\jni\su\su_exec_data.h"
)

if exist "%root_path%src\jni\lib_su_env\lib_su_env_data.h" (
    del "%root_path%src\jni\lib_su_env\lib_su_env_data.h"
)

if exist "%root_path%src\jni\3rdparty\upx\upx_exec_data.h" (
    del "%root_path%src\jni\3rdparty\upx\upx_exec_data.h"
)

if exist "%root_path%src\jni\lib_root_server\res.h" (
    del "%root_path%src\jni\lib_root_server\res.h"
)

if exist "%root_path%src\jni\su\res.h" (
    del "%root_path%src\jni\su\res.h"
)

if exist "%root_path%src\jni\lib_su_env\res.h" (
    del "%root_path%src\jni\lib_su_env\res.h"
)

if exist "%root_path%src\jni\3rdparty\upx\res.h" (
    del "%root_path%src\jni\3rdparty\upx\res.h"
)

if exist "%root_path%src\jni\lib_root_server\index.gz.bin" (
    del "%root_path%src\jni\lib_root_server\index.gz.bin"
)

if exist "%root_path%src\jni\lib_root_server\index_html_gz_data.h" (
    del "%root_path%src\jni\lib_root_server\index_html_gz_data.h"
)

if exist "%root_path%\src\obj" (
    rmdir /S /Q "%root_path%\src\obj"
)

if exist "%root_path%\lib" (
    rmdir /S /Q "%root_path%\lib"
)

if exist "%root_path%\src\jni\su\libs" (
    rmdir /S /Q "%root_path%\src\jni\su\libs"
)

if exist "%root_path%\src\jni\su\obj" (
    rmdir /S /Q "%root_path%\src\jni\su\obj"
) 

if exist "%root_path%\src\jni\lib_su_env\libs" (
    rmdir /S /Q "%root_path%\src\jni\lib_su_env\libs"
)

if exist "%root_path%\src\jni\lib_su_env\obj" (
    rmdir /S /Q "%root_path%\src\jni\lib_su_env\obj"
) 

if exist "%root_path%\src\jni\lib_root_server\libs" (
    rmdir /S /Q "%root_path%\src\jni\lib_root_server\libs"
)

if exist "%root_path%\src\jni\lib_root_server\obj" (
    rmdir /S /Q "%root_path%\src\jni\lib_root_server\obj"
) 
