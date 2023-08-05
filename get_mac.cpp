#include <iostream>
#include <string>
#include <fstream>

#include "mac.h"

Mac get_mac(const std::string& interface) {
    std::string result;
    std::ifstream file("/sys/class/net/" + interface + "/address");

    if (file.is_open()) {
        std::getline(file, result);
        file.close();
    } else {
        result = "Error: Unable to open the file.";
    }
    return Mac(result);
}
