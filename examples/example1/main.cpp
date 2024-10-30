// main.cpp
#include "../../Logger.h"
#include <thread>
#include <vector>
#include <random>
#include <chrono>

void clientTask(int clientId) {
    using namespace LoggerNS;
    std::string clientName = "Client" + std::to_string(clientId);
    std::set<std::string> tags = {"client", clientName};

    // Start a timer for the client's task
    START_TIMER(clientName + "_task");

    LOG_INFO("client", tags, [clientName]() {
        return clientName + " started task.";
    });

    // Simulate some work with random duration
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100, 500);
    int sleepTime = dis(gen);

    std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));

    LOG_DEBUG("client", tags, [clientName, sleepTime]() {
        return clientName + " is processing data for " + std::to_string(sleepTime) + " ms.";
    });

    // Simulate a possible error
    if (dis(gen) % 5 == 0) {
        LOG_ERROR("client", tags, [clientName]() {
            return clientName + " encountered an error during processing.";
        });
    }

    LOG_INFO("client", tags, [clientName]() {
        return clientName + " completed task.";
    });

    // End the timer and log the elapsed time
    END_TIMER(clientName + "_task", LoggerNS::LogLevel::INFO, "performance", tags);
}

int main() {
    using namespace LoggerNS;
    Logger& logger = Logger::getInstance();

    // Load configuration from JSON file (optional)
    try {
        logger.loadConfiguration("config.json");
    } catch (const std::exception& e) {
        std::cerr << "Failed to load configuration: " << e.what() << std::endl;

        // Fallback configuration
        // Add console output
        logger.addOutput(std::make_shared<std::ostream>(std::cout.rdbuf()), LogLevel::DEBUG);

        // Add file output
        auto fileStream = std::make_shared<std::ofstream>("server.log", std::ios::app);
        if (fileStream->is_open()) {
            logger.addOutput(fileStream, LogLevel::DEBUG, "%Y-%m-%d %H:%M:%S", "json", false);
        }
    }

    // Enable asynchronous logging
    logger.enableAsynchronousLogging(true);

    // Start server simulation
    LOG_INFO("server", {"startup"}, []() {
        return "Server started.";
    });

    // Simulate multiple client connections
    const int clientCount = 10;
    std::vector<std::thread> clientThreads;
    for (int i = 1; i <= clientCount; ++i) {
        clientThreads.emplace_back(clientTask, i);
    }

    // Wait for all clients to complete
    for (auto& t : clientThreads) {
        t.join();
    }

    LOG_INFO("server", {"shutdown"}, []() {
        return "Server shutting down.";
    });

    // Flush and shutdown the logger
    logger.flush();
    logger.enableAsynchronousLogging(false);

    return 0;
}
