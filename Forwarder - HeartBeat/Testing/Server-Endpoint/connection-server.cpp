#include <iostream>
#include <thread>

int main() {
    std::cout << "Available Cores: " << std::thread::hardware_concurrency() << std::endl;
    return 0;
}
