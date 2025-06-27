@echo off
cd /d "%~dp0"

set "root_path=%~dp0"

if exist kernel_root_kit\core\rootkit_lib_root_server_data.h (
    del kernel_root_kit\core\rootkit_lib_root_server_data.h
)

if exist kernel_root_kit\core\rootkit_su_exec_data.h (
    del kernel_root_kit\core\rootkit_su_exec_data.h
)

if exist kernel_root_kit\core\rootkit_lib_su_env_data.h (
    del kernel_root_kit\core\rootkit_lib_su_env_data.h
)

if exist kernel_root_kit\core\rootkit_upx_data.h (
    del kernel_root_kit\core\rootkit_upx_data.h
)

if exist su\res.h (
    del su\res.h
)

if exist lib_su_env\res.h (
    del lib_su_env\res.h
)

if exist lib_root_server\res.h (
    del lib_root_server\res.h
)

if exist lib_root_server\index.gz.bin (
    del lib_root_server\index.gz.bin
)

if exist lib_root_server\index_html_gz_data.h (
    del lib_root_server\index_html_gz_data.h
)

if exist 3rdparty\upx\res.h (
    del 3rdparty\upx\res.h
)

if exist "%root_path%\su\libs" (
    rmdir /S /Q "%root_path%\su\libs"
)

if exist "%root_path%\su\obj" (
    rmdir /S /Q "%root_path%\su\obj"
) 

if exist "%root_path%\lib_su_env\libs" (
    rmdir /S /Q "%root_path%\lib_su_env\libs"
)

if exist "%root_path%\lib_su_env\obj" (
    rmdir /S /Q "%root_path%\lib_su_env\obj"
) 

if exist "%root_path%\lib_root_server\libs" (
    rmdir /S /Q "%root_path%\lib_root_server\libs"
)

if exist "%root_path%\lib_root_server\obj" (
    rmdir /S /Q "%root_path%\lib_root_server\obj"
) 

if exist "%root_path%\..\libs" (
    rmdir /S /Q "%root_path%\..\libs"
)

if exist "%root_path%\..\obj" (
    rmdir /S /Q "%root_path%\..\obj"
) 
