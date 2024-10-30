#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <map>
#include <set>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <memory>
#include <stdexcept>
#include <fstream>

// Include the nlohmann/json library for JSON parsing
#include <json.hpp>

namespace LoggerNS {

using json = nlohmann::json;

/**
 * @brief Enumeration for log levels.
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
    OFF // For disabling logging
};

/**
 * @brief Structure for log messages.
 */
struct LogMessage {
    LogLevel level;
    std::string category;
    std::set<std::string> tags;
    std::string message;
    std::string timestamp;
    std::string file;
    int line;
    std::string function;
};

/**
 * @brief Class representing an output destination.
 */
class Output {
public:
    Output(std::shared_ptr<std::ostream> os, LogLevel level, const std::string& format = "%Y-%m-%d %H:%M:%S",
           const std::string& outputFormat = "plain", bool useANSIColors = true)
        : stream(std::move(os)), logLevel(level), timestampFormat(format),
          outputFormat(outputFormat), useANSIColors(useANSIColors) {}

    void log(const LogMessage& msg) {
        if (msg.level < logLevel || msg.level == LogLevel::OFF) return;

        std::string formattedMessage;
        try {
            formattedMessage = formatMessage(msg);
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(errorMutex);
            std::cerr << "Formatting error: " << e.what() << std::endl;
            return;
        }

        std::lock_guard<std::mutex> lock(streamMutex);
        try {
            (*stream) << formattedMessage;
            stream->flush();
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(errorMutex);
            std::cerr << "Logging error: Failed to write to stream. Error: " << e.what() << "\n";
            std::cerr << formattedMessage;
            std::cerr.flush();
        }
    }

    void setLogLevel(LogLevel level) noexcept { logLevel = level; }
    LogLevel getLogLevel() const noexcept { return logLevel; }
    void setTimestampFormat(const std::string& format) {
        std::lock_guard<std::mutex> lock(streamMutex);
        timestampFormat = format;
    }
    void setOutputFormat(const std::string& format) {
        std::lock_guard<std::mutex> lock(streamMutex);
        outputFormat = format;
    }
    void enableANSIColors(bool enable) noexcept { useANSIColors = enable; }

    std::shared_ptr<std::ostream> getStream() const noexcept { return stream; }


private:
    std::shared_ptr<std::ostream> stream;
    LogLevel logLevel;
    std::string timestampFormat;
    std::string outputFormat;
    bool useANSIColors;
    mutable std::mutex streamMutex;
    mutable std::mutex errorMutex;

    std::string formatMessage(const LogMessage& msg) {
        std::ostringstream oss;
        std::string colorCode = useANSIColors ? getANSIColorCode(msg.level) : "";
        std::string resetCode = useANSIColors ? "\033[0m" : "";

        if (outputFormat == "json") {
            json j;
            j["timestamp"] = msg.timestamp;
            j["level"] = logLevelToString(msg.level);
            j["category"] = msg.category;
            j["message"] = msg.message;
            if (!msg.file.empty()) {
                j["file"] = msg.file;
                j["line"] = msg.line;
                j["function"] = msg.function;
            }
            if (!msg.tags.empty()) {
                j["tags"] = msg.tags;
            }
            oss << colorCode << j.dump() << resetCode << "\n";
        } else {
            oss << colorCode << msg.timestamp << " ["
                << logLevelToString(msg.level) << "] ["
                << msg.category << "] ";
            if (!msg.tags.empty()) {
                oss << "[Tags:";
                for (const auto& tag : msg.tags) {
                    oss << " " << tag;
                }
                oss << "] ";
            }
            oss << msg.message;
            if (!msg.file.empty()) {
                oss << " (" << msg.file << ":" << msg.line << " in " << msg.function << ")";
            }
            oss << resetCode << "\n";
        }

        return oss.str();
    }

    std::string getANSIColorCode(LogLevel level) const noexcept {
        switch (level) {
            case LogLevel::DEBUG: return "\033[36m"; // Cyan
            case LogLevel::INFO: return "\033[32m"; // Green
            case LogLevel::WARNING: return "\033[33m"; // Yellow
            case LogLevel::ERROR: return "\033[31m"; // Red
            case LogLevel::CRITICAL: return "\033[41m"; // Red background
            default: return "";
        }
    }

    std::string logLevelToString(LogLevel level) const noexcept {
        switch (level) {
            case LogLevel::DEBUG: return "DEBUG";
            case LogLevel::INFO: return "INFO";
            case LogLevel::WARNING: return "WARNING";
            case LogLevel::ERROR: return "ERROR";
            case LogLevel::CRITICAL: return "CRITICAL";
            case LogLevel::OFF: return "OFF";
            default: return "UNKNOWN";
        }
    }
};

/**
 * @brief Logger class providing advanced logging functionalities.
 */
class Logger {
public:

    /**
     * @brief Get the global log level.
     *
     * @return The global log level.
     *
     * This function returns the global log level set by the user. By default, the
     * global log level is set to LogLevel::INFO. The global log level can be
     * changed by calling the Logger::setGlobalLogLevel function.
     */
    LogLevel getGlobalLogLevel() const noexcept {
        return globalLogLevel.load(std::memory_order_relaxed);
    }

    // Get the singleton instance of the logger
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }

    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // Configuration methods
    void addOutput(std::shared_ptr<std::ostream> os, LogLevel level,
                   const std::string& timestampFormat = "%Y-%m-%d %H:%M:%S",
                   const std::string& outputFormat = "plain", bool useANSIColors = true) {
        auto output = std::make_shared<Output>(std::move(os), level, timestampFormat, outputFormat, useANSIColors);
        std::lock_guard<std::mutex> lock(outputsMutex);
        outputs.emplace_back(std::move(output));
    }

    void setGlobalLogLevel(LogLevel level) noexcept {
        globalLogLevel.store(level, std::memory_order_relaxed);
    }

    void setCategoryLogLevel(const std::string& category, LogLevel level) {
        std::lock_guard<std::mutex> lock(categoriesMutex);
        categoryLogLevels[category] = level;
    }

    void addCategory(const std::string& category) {
        std::lock_guard<std::mutex> lock(categoriesMutex);
        categories.insert(category);
    }

    void removeCategory(const std::string& category) {
        std::lock_guard<std::mutex> lock(categoriesMutex);
        categories.erase(category);
    }

    void addTag(const std::string& tag) {
        std::lock_guard<std::mutex> lock(tagsMutex);
        tags.insert(tag);
    }

    void removeTag(const std::string& tag) {
        std::lock_guard<std::mutex> lock(tagsMutex);
        tags.erase(tag);
    }

    void setTimestampFormat(const std::string& format) {
        std::lock_guard<std::mutex> lock(outputsMutex);
        for (const auto& output : outputs) {
            output->setTimestampFormat(format);
        }
    }

    void setOutputFormat(const std::string& format) {
        std::lock_guard<std::mutex> lock(outputsMutex);
        for (const auto& output : outputs) {
            output->setOutputFormat(format);
        }
    }

    void enableAsynchronousLogging(bool enable) {
        bool expected = !enable;
        if (asynchronousLogging.compare_exchange_strong(expected, enable)) {
            if (enable && !isRunning.load(std::memory_order_acquire)) {
                isRunning.store(true, std::memory_order_release);
                loggingThread = std::thread(&Logger::loggingThreadFunction, this);
            } else if (!enable && isRunning.load(std::memory_order_acquire)) {
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    isRunning.store(false, std::memory_order_release);
                }
                queueCV.notify_all();
                if (loggingThread.joinable()) {
                    loggingThread.join();
                }
            }
        }
    }

    void flush() {
        if (asynchronousLogging.load(std::memory_order_acquire)) {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this]() { return logQueue.empty(); });
        }
        // Flush outputs
        std::lock_guard<std::mutex> lock(outputsMutex);
        for (const auto& output : outputs) {
            if (auto stream = output->getStream()) {
                stream->flush();
            }
        }
    }

    void loadConfiguration(const std::string& configFilePath) {
        initializeFromConfig(configFilePath);
    }

    // Logging method with lazy evaluation
    void log(LogLevel level, const std::string& category, const std::set<std::string>& msgTags,
             std::function<std::string()> messageGenerator,
             const std::string& file = "", int line = 0, const std::string& function = "") {
        if (level < globalLogLevel.load(std::memory_order_relaxed) || level == LogLevel::OFF) return;

        {
            std::lock_guard<std::mutex> lock(categoriesMutex);
            if (!categories.empty() && categories.find(category) == categories.end()) {
                return;
            }
            auto it = categoryLogLevels.find(category);
            if (it != categoryLogLevels.end() && level < it->second) {
                return;
            }
        }

        {
            std::lock_guard<std::mutex> lock(tagsMutex);
            if (!tags.empty()) {
                bool tagFound = false;
                for (const auto& tag : msgTags) {
                    if (tags.find(tag) != tags.end()) {
                        tagFound = true;
                        break;
                    }
                }
                if (!tagFound) return;
            }
        }

        // Construct the log message
        LogMessage msg;
        msg.level = level;
        msg.category = category;
        msg.tags = msgTags;
        msg.file = file;
        msg.line = line;
        msg.function = function;

        try {
            // Lazy evaluation
            msg.message = messageGenerator();
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(errorMutex);
            std::cerr << "Logging error: Exception in message generation: " << e.what() << std::endl;
            return;
        }

        msg.timestamp = getCurrentTimestamp();

        if (asynchronousLogging.load(std::memory_order_acquire)) {
            std::unique_lock<std::mutex> lock(queueMutex);
            if (logQueue.size() >= maxQueueSize) {
                // Optionally handle queue full scenario
                // For now, we drop the message
                return;
            }
            logQueue.emplace(std::move(msg));
            lock.unlock();
            queueCV.notify_one();
        } else {
            writeToOutputs(msg);
        }
    }

    // Timer methods
    void startTimer(const std::string& timerName) {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(timersMutex);
        timers[timerName] = now;
    }

    void endTimer(const std::string& timerName, LogLevel level, const std::string& category,
                  const std::set<std::string>& msgTags = {}, const std::string& file = "",
                  int line = 0, const std::string& function = "") {
        auto endTime = std::chrono::steady_clock::now();

        std::chrono::steady_clock::time_point startTime;
        {
            std::lock_guard<std::mutex> lock(timersMutex);
            auto it = timers.find(timerName);
            if (it != timers.end()) {
                startTime = it->second;
                timers.erase(it);
            } else {
                // Timer not found
                return;
            }
        }

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

        log(level, category, msgTags, [duration, timerName]() {
            return "Timer [" + timerName + "] elapsed time: " + std::to_string(duration) + " ms";
        }, file, line, function);
    }

    // Destructor
    ~Logger() noexcept {
        try {
            enableAsynchronousLogging(false);
            flush();
        } catch (...) {
            // Suppress all exceptions in destructor
        }
    }

private:
    // Private constructor for singleton pattern
    Logger() : globalLogLevel(LogLevel::INFO), asynchronousLogging(false), isRunning(false), maxQueueSize(1000) {}

    void writeToOutputs(const LogMessage& msg) {
        std::lock_guard<std::mutex> lock(outputsMutex);
        for (const auto& output : outputs) {
            if (output) {
                output->log(msg);
            }
        }
    }

    void loggingThreadFunction() {
        while (isRunning.load(std::memory_order_acquire)) {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this]() { return !logQueue.empty() || !isRunning.load(std::memory_order_acquire); });

            while (!logQueue.empty()) {
                LogMessage msg = std::move(logQueue.front());
                logQueue.pop();
                lock.unlock();

                writeToOutputs(msg);

                lock.lock();
            }
        }

        // Process any remaining messages
        while (!logQueue.empty()) {
            LogMessage msg = std::move(logQueue.front());
            logQueue.pop();
            writeToOutputs(msg);
        }
    }

    std::string getCurrentTimestamp() const {
        auto now = std::chrono::system_clock::now();
        std::time_t time_t_now = std::chrono::system_clock::to_time_t(now);

        std::tm tm_now;
#if defined(_MSC_VER) || defined(__MINGW32__)
        localtime_s(&tm_now, &time_t_now);
#else
        localtime_r(&time_t_now, &tm_now);
#endif

        std::ostringstream ss;
        ss << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    void initializeFromConfig(const std::string& configFilePath) {
        std::ifstream configFile(configFilePath);
        if (!configFile.is_open()) {
            throw std::runtime_error("Cannot open configuration file: " + configFilePath);
        }

        json configJson;
        try {
            configFile >> configJson;
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to parse configuration file: " + std::string(e.what()));
        }

        // Set global log level
        if (configJson.contains("globalLogLevel")) {
            std::string levelStr = configJson["globalLogLevel"];
            globalLogLevel.store(stringToLogLevel(levelStr), std::memory_order_relaxed);
        }

        // Configure outputs
        if (configJson.contains("outputs")) {
            for (const auto& outputConfig : configJson["outputs"]) {
                std::string type = outputConfig["type"];
                std::string levelStr = outputConfig["logLevel"];
                LogLevel level = stringToLogLevel(levelStr);
                std::string timestampFormat = outputConfig.value("timestampFormat", "%Y-%m-%d %H:%M:%S");
                std::string outputFormat = outputConfig.value("outputFormat", "plain");
                bool useANSIColors = outputConfig.value("useANSIColors", true);

                if (type == "file") {
                    std::string filePath = outputConfig["filePath"];
                    auto ofs = std::make_shared<std::ofstream>(filePath, std::ios::app);
                    if (!ofs->is_open()) {
                        throw std::runtime_error("Cannot open log file: " + filePath);
                    }
                    addOutput(ofs, level, timestampFormat, outputFormat, useANSIColors);
                } else if (type == "console") {
                    addOutput(std::make_shared<std::ostream>(std::cout.rdbuf()), level, timestampFormat, outputFormat, useANSIColors);
                }
            }
        }
    }

    LogLevel stringToLogLevel(const std::string& levelStr) const noexcept {
        if (levelStr == "DEBUG") return LogLevel::DEBUG;
        if (levelStr == "INFO") return LogLevel::INFO;
        if (levelStr == "WARNING") return LogLevel::WARNING;
        if (levelStr == "ERROR") return LogLevel::ERROR;
        if (levelStr == "CRITICAL") return LogLevel::CRITICAL;
        if (levelStr == "OFF") return LogLevel::OFF;
        return LogLevel::INFO; // Default
    }

    // Member variables
    std::vector<std::shared_ptr<Output>> outputs;
    mutable std::mutex outputsMutex;

    std::atomic<LogLevel> globalLogLevel;
    std::map<std::string, LogLevel> categoryLogLevels;
    std::set<std::string> categories;
    mutable std::mutex categoriesMutex;

    std::set<std::string> tags;
    mutable std::mutex tagsMutex;

    std::queue<LogMessage> logQueue;
    mutable std::mutex queueMutex;
    std::condition_variable queueCV;

    std::atomic<bool> asynchronousLogging;
    std::atomic<bool> isRunning;
    std::thread loggingThread;
    size_t maxQueueSize;

    std::map<std::string, std::chrono::steady_clock::time_point> timers;
    mutable std::mutex timersMutex;

    mutable std::mutex errorMutex;
};

// Convenience Macros for capturing source location and lazy evaluation

#define LOG(level, category, tags, ...) \
    do { \
        LoggerNS::Logger& logger = LoggerNS::Logger::getInstance(); \
        if (level >= logger.getGlobalLogLevel() && level != LoggerNS::LogLevel::OFF) { \
            logger.log(level, category, tags, __VA_ARGS__, __FILE__, __LINE__, __func__); \
        } \
    } while(0)

#define LOG_DEBUG(category, tags, ...) \
    LOG(LoggerNS::LogLevel::DEBUG, category, tags, __VA_ARGS__)

#define LOG_INFO(category, tags, ...) \
    LOG(LoggerNS::LogLevel::INFO, category, tags, __VA_ARGS__)

#define LOG_WARNING(category, tags, ...) \
    LOG(LoggerNS::LogLevel::WARNING, category, tags, __VA_ARGS__)

#define LOG_ERROR(category, tags, ...) \
    LOG(LoggerNS::LogLevel::ERROR, category, tags, __VA_ARGS__)

#define LOG_CRITICAL(category, tags, ...) \
    LOG(LoggerNS::LogLevel::CRITICAL, category, tags, __VA_ARGS__)
    
#define START_TIMER(timerName) \
    LoggerNS::Logger::getInstance().startTimer(timerName)

#define END_TIMER(timerName, level, category, tags) \
    LoggerNS::Logger::getInstance().endTimer(timerName, level, category, tags, __FILE__, __LINE__, __func__)

} // namespace LoggerNS

#endif // LOGGER_H
