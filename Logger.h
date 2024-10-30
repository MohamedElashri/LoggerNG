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
    /**
     * @brief Constructor for Output.
     *
     * @param os The output stream where the log messages are written.
     * @param level The log level for this output.
     * @param format The timestamp format.
     * @param outputFormat The log message output format.
     * @param useANSIColors Whether to use ANSI escape sequences to color log messages.
     */
    Output(std::shared_ptr<std::ostream> os, LogLevel level, const std::string& format = "%Y-%m-%d %H:%M:%S",
           const std::string& outputFormat = "plain", bool useANSIColors = true)
        : stream(std::move(os)), logLevel(level), timestampFormat(format),
          outputFormat(outputFormat), useANSIColors(useANSIColors) {}

    /**
     * @brief Write a log message to the output stream.
     *
     * @param msg The log message to write.
     *
     * If the log level of the message is lower than the log level of this output
     * or if the log level is set to LogLevel::OFF, the message is not written.
     *
     * This function first formats the log message using the formatMessage
     * function and then writes the formatted message to the output stream.
     *
     * If formatting fails, a message is written to the standard error stream
     * indicating the error.
     *
     * If writing to the output stream fails, a message is written to the standard
     * error stream indicating the error and the original log message.
     */
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


    /**
     * @brief Set the log level for this logger.
     *
     * This function sets the log level for this logger instance. Log messages with a
     * level lower than the set log level will be ignored and not written to the
     * output stream.
     *
     * @param level The new log level to set.
     */
    void setLogLevel(LogLevel level) noexcept;
    
    
    /**
     * @brief Get the current log level for this logger.
     *
     * This function returns the current log level set for this logger instance.
     *
     * @return The current log level.
     */
    LogLevel getLogLevel() const noexcept;
    void setLogLevel(LogLevel level) noexcept { logLevel = level; }
    LogLevel getLogLevel() const noexcept { return logLevel; }

    /**
     * @brief Set the timestamp format string.
     *
     * This function sets the format string used to format the timestamp in log
     * messages. The format string is used with std::strftime. The default format
     * string is "%Y-%m-%d %H:%M:%S".
     *
     * @param format The format string.
     */
    void setTimestampFormat(const std::string& format) {
        std::lock_guard<std::mutex> lock(streamMutex);
        timestampFormat = format;
    }
    /**
     * @brief Set the output format string.
     *
     * This function sets the format string used to format the output log messages.
     * The format string is used with std::ostream. The default format string is
     * "plain". The format string can be set to "json" to output log messages in
     * JSON format.
     *
     * @param format The format string.
     */
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

    /**
     * @brief Format a log message based on the output format.
     *
     * This function formats the given log message according to the output format
     * set for this logger. If the output format is "json", the log message is
     * formatted as a JSON object. Otherwise, the log message is formatted as a
     * plain text string. The log message is returned as a string.
     *
     * @param msg The log message to format.
     *
     * @return The formatted log message as a string.
     */
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

    /**
     * @brief Returns an ANSI escape sequence to set the text color based on the log level.
     *
     * @param level The log level.
     * @return The ANSI escape sequence for the given log level.
     *
     * The mapping of log levels to colors is as follows:
     * - LogLevel::DEBUG: Cyan
     * - LogLevel::INFO: Green
     * - LogLevel::WARNING: Yellow
     * - LogLevel::ERROR: Red
     * - LogLevel::CRITICAL: Red background
     * - All other values: No color (empty string)
     */
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

    /**
     * @brief Converts a LogLevel to its string representation.
     *
     * @param level The LogLevel to convert.
     * @return The string representation of the LogLevel.
     *
     * The mapping of LogLevel values to strings is as follows:
     * - LogLevel::DEBUG: "DEBUG"
     * - LogLevel::INFO: "INFO"
     * - LogLevel::WARNING: "WARNING"
     * - LogLevel::ERROR: "ERROR"
     * - LogLevel::CRITICAL: "CRITICAL"
     * - LogLevel::OFF: "OFF"
     * - All other values: "UNKNOWN"
     */
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

    /**
     * @brief Add a log output.
     *
     * @param os The output stream to which log messages are written.
     * @param level The log level for this output.
     * @param timestampFormat The timestamp format string.
     * @param outputFormat The log message output format.
     * @param useANSIColors Whether to use ANSI escape sequences to color log messages.
     *
     * This function adds a log output to the logger. The log output is configured
     * with the given log level, timestamp format, output format, and whether to
     * use ANSI escape sequences to color log messages. The log output is added to
     * the list of outputs and the logger will write log messages to this output
     * stream if the log level is greater than or equal to the log level of the
     * output.
     */
    void addOutput(std::shared_ptr<std::ostream> os, LogLevel level,
                   const std::string& timestampFormat = "%Y-%m-%d %H:%M:%S",
                   const std::string& outputFormat = "plain", bool useANSIColors = true) {
        auto output = std::make_shared<Output>(std::move(os), level, timestampFormat, outputFormat, useANSIColors);
        std::lock_guard<std::mutex> lock(outputsMutex);
        outputs.emplace_back(std::move(output));
    }

    /**
     * @brief Set the global log level for the logger.
     *
     * This function sets the global log level, which determines the minimum
     * severity of log messages that will be processed by the logger. Log messages
     * with a severity lower than the global log level will be ignored.
     *
     * @param level The LogLevel to set as the global log level.
     */
    void setGlobalLogLevel(LogLevel level) noexcept {
        globalLogLevel.store(level, std::memory_order_relaxed);
    }

    /**
     * @brief Set the log level for a category.
     *
     * This function sets the log level for a category. Log messages with a
     * severity lower than the log level set for a category will be ignored.
     *
     * @param category The category name.
     * @param level The LogLevel to set for the category.
     */
    void setCategoryLogLevel(const std::string& category, LogLevel level) {
        std::lock_guard<std::mutex> lock(categoriesMutex);
        categoryLogLevels[category] = level;
    }

    /**
     * @brief Add a category to the logger.
     *
     * This function adds a category to the logger. Log messages with a category
     * that is not in the list of categories will be ignored.
     *
     * @param category The category name.
     */
    void addCategory(const std::string& category) {
        std::lock_guard<std::mutex> lock(categoriesMutex);
        categories.insert(category);
    }

    /**
     * @brief Remove a category from the logger.
     *
     * This function removes a category from the logger. Log messages with a
     * category that is not in the list of categories will be ignored.
     *
     * @param category The category name to remove.
     */
    void removeCategory(const std::string& category) {
        std::lock_guard<std::mutex> lock(categoriesMutex);
        categories.erase(category);
    }

    /**
     * @brief Add a tag to the logger.
     *
     * This function adds a tag to the logger. Log messages with a tag that is
     * not in the list of tags will be ignored.
     *
     * @param tag The tag name to add.
     */
    void addTag(const std::string& tag) {
        std::lock_guard<std::mutex> lock(tagsMutex);
        tags.insert(tag);
    }

    /**
     * @brief Remove a tag from the logger.
     *
     * This function removes a tag from the logger. Log messages with a tag that
     * is not in the list of tags will be ignored.
     *
     * @param tag The tag name to remove.
     */
    void removeTag(const std::string& tag) {
        std::lock_guard<std::mutex> lock(tagsMutex);
        tags.erase(tag);
    }

    /**
     * @brief Set the timestamp format for all outputs.
     *
     * This function sets the format string used to format the timestamp in log
     * messages for all output destinations managed by the logger. The format
     * string is used with std::strftime. The default format string is "%Y-%m-%d %H:%M:%S".
     *
     * @param format The format string.
     */
    void setTimestampFormat(const std::string& format) {
        std::lock_guard<std::mutex> lock(outputsMutex);
        for (const auto& output : outputs) {
            output->setTimestampFormat(format);
        }
    }

    /**
     * @brief Set the output format for all outputs.
     *
     * This function sets the format string used to format the log messages
     * for all output destinations managed by the logger. The format string
     * can be "plain" for plain text or "json" for JSON formatted log messages.
     *
     * @param format The format string to set for the output log messages.
     */
    void setOutputFormat(const std::string& format) {
        std::lock_guard<std::mutex> lock(outputsMutex);
        for (const auto& output : outputs) {
            output->setOutputFormat(format);
        }
    }

    /**
     * @brief Enable or disable asynchronous logging.
     *
     * This function controls the asynchronous logging mechanism. When enabled,
     * log messages are processed in a separate thread, allowing the main thread
     * to continue execution without waiting for logging to complete. When
     * disabled, the logging thread is stopped, and any remaining messages in
     * the queue are processed.
     *
     * @param enable If true, asynchronous logging is enabled. If false,
     * asynchronous logging is disabled.
     */
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

    /**
     * @brief Flush the log queue and output streams.
     *
     * This function will wait until all log messages in the queue have been processed
     * by the logging thread (if asynchronous logging is enabled) and then flush all
     * output streams. This is useful for ensuring that all log messages are written to
     * their output destinations before the program exits.
     */
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

    /**
     * @brief Load the logger configuration from a JSON file.
     *
     * @param configFilePath The path to the JSON configuration file.
     *
     * This function will load the logger configuration from the given JSON
     * file and apply it to the logger. The configuration file should contain
     * the same format as the configuration accepted by the Logger::initializeFromConfig
     * function. If the configuration file cannot be loaded or parsed, an
     * exception is thrown.
     */
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

    /**
     * @brief Function for processing log messages in a separate thread.
     *
     * This function runs in a separate thread when asynchronous logging is enabled.
     * It continuously checks for new log messages in the queue and processes them
     * by writing them to the configured outputs. The thread waits for new messages
     * to be added to the queue or until the asynchronous logging is disabled. 
     * Once disabled, it ensures all remaining messages in the queue are processed 
     * before the thread exits.
     */
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

    /**
     * @brief Get the current timestamp as a formatted string.
     *
     * This function retrieves the current system time and formats it
     * into a string representation using the format "%Y-%m-%d %H:%M:%S".
     * It is compatible with both MSC and non-MSC environments for
     * converting the time to a local `std::tm` structure.
     *
     * @return The current timestamp formatted as a string.
     */
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

    /**
     * @brief Load the logger configuration from a JSON file.
     *
     * This function will load the logger configuration from the given JSON
     * file and apply it to the logger. The configuration file should contain
     * the same format as the configuration accepted by the Logger::initializeFromConfig
     * function. If the configuration file cannot be loaded or parsed, an
     * exception is thrown.
     *
     * The format of the JSON configuration file should be as follows:
     * @code{.json}
     * {
     *     "globalLogLevel": "DEBUG",
     *     "outputs": [
     *         {
     *             "type": "file",
     *             "filePath": "server.log",
     *             "logLevel": "DEBUG",
     *             "timestampFormat": "%Y-%m-%d %H:%M:%S",
     *             "outputFormat": "plain",
     *             "useANSIColors": false
     *         }
     *     ]
     * }
     * @endcode
     *
     * @param configFilePath The path to the JSON configuration file.
     */
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

    /**
     * @brief Convert a log level string to a LogLevel.
     *
     * This function takes a string representation of a log level and converts
     * it to a LogLevel enumeration value. The possible string values are
     * "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", and "OFF". If an
     * invalid log level string is given, the function returns LogLevel::INFO.
     *
     * @param levelStr The log level string to convert.
     * @return The LogLevel enumeration value for the given log level string.
     */
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
