#pragma once
#include <iostream>

namespace kernel_root {
typedef enum {
    app_dynlib_status_unknown = 0,
    app_dynlib_status_running,
    app_dynlib_status_not_running
} app_dynlib_status;
}
