#pragma once
#include <string.h>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

namespace {
std::string ROOT_KEY;
int PORT = 0;
char LOG_FILE[] = {'/','s','d','c','a','r','d','/','r','o','o','t','_','s','e','r','v','e','r','.','l','o','g','\0'};
void writeToLog(const std::string & message) {
    printf("%s\n", message.c_str());
    // std::ofstream logFile(LOG_FILE, std::ios::app);
    // if (!logFile) {
    //     std::cerr << "Error opening file" << std::endl;
    //     return;
    // }
    // logFile << message << std::endl;
    // logFile.close();
    // std::cout << message << std::endl;
}

std::string GetHttpHead_200(long lLen, bool append_gzip = false) {
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

}
