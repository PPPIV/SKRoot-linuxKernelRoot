#pragma once
#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <tuple>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "cJSON.h"

static void writeToLog(const std::string & message) {
    // printf("%s\n", message.c_str());
    // std::ofstream logFile("/sdcard/web_server.log", std::ios::app);
    // if (!logFile) {
    //     std::cerr << "Error opening file" << std::endl;
    //     return;
    // }
    // logFile << message << std::endl;
    // logFile.close();
    // std::cout << message << std::endl;
}

static std::string GetHttpHead_200(long lLen, bool append_gzip = false) {
    std::stringstream sstrHead;
    sstrHead << "HTTP/1.1 200 OK\r\n";
    sstrHead << "Access-Control-Allow-Origin: *\r\n";
    sstrHead << "Connection: keep-alive\r\n";
    sstrHead << "Content-Length: " << lLen << "\r\n";
    sstrHead << "Content-Type: text/html; charset=UTF-8\r\n";
	if (append_gzip) {
        sstrHead << "Content-Encoding: gzip\r\n";
    }
    sstrHead << "\r\n";
    return sstrHead.str();
}

static std::string CreateJsonBody(const std::vector<std::tuple<std::string, std::string>>& keyValuePairs) {
    cJSON *root = cJSON_CreateObject();
    if(!root) {
        return {};
    }
    for (const auto& pair : keyValuePairs) {
        cJSON_AddItemToObject(root, std::get<0>(pair).c_str(), cJSON_CreateString(std::get<1>(pair).c_str()));
    }

    char *json = cJSON_Print(root);
    std::string jsonStr(json);
    free(json);
    cJSON_Delete(root);
    return jsonStr;
}

static std::string GetMiddleJsonString(std::string_view text) {
    std::string jsonString;
    int jsonStart = text.find("{");
	int jsonEnd = text.find_last_of("}");
	if(jsonStart != std::string::npos && jsonEnd != std::string::npos) {
        jsonString = text.substr(jsonStart, jsonEnd - jsonStart + 1);
	}
    return jsonString;
}
