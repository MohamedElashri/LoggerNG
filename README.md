# LoggerNG: Advanced Logger for C++ programs

An advanced, flexible, and memory-safe logging utility for C++ programs. This header-only library provides structured, categorized logging with multiple log levels, timestamping, ANSI color coding, asynchronous logging, and more.

---

## Table of Contents

- [Motivation](#motivation)
- [Basic Usage](#basic-usage)
- [Features](#features)
- [Feature Examples](#feature-examples)
  - [Multiple Log Levels](#multiple-log-levels)
  - [Timestamping](#timestamping)
  - [ANSI Color Coding](#ansi-color-coding)
  - [Structured Formatting](#structured-formatting)
  - [Conditional Logging](#conditional-logging)
  - [Output Control](#output-control)
  - [Logging Categories and Tags](#logging-categories-and-tags)
  - [Asynchronous Logging](#asynchronous-logging)
  - [Custom Timestamp Format](#custom-timestamp-format)
  - [Source Location Metadata](#source-location-metadata)
  - [Profiling and Benchmarking](#profiling-and-benchmarking)
  - [Configuration File Support](#configuration-file-support)
- [Advanced Examples](#advanced-examples)
- [Memory Safety Guidelines](#memory-safety-guidelines)
- [Contributing](#contributing)
- [Available Methods](#available-methods)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Motivation

In many C++ CLI projects, setting up a consistent and flexible logging system can be a repetitive and time-consuming task. This logging utility aims to provide a standardized, memory-safe way to handle logging across different projects, reducing the need to reinvent the wheel each time. It may not be the most feature-rich or performant logger available, but it strikes a balance between functionality, safety, and ease of integration.

---

## Basic Usage

1. **Include the Header File**

   ```cpp
   #include "Logger.hpp"
   ```

2. **Configure the Logger**

   ```cpp
   using namespace LoggerNS;

   // Get the singleton instance of the logger
   Logger& logger = Logger::getInstance();

   // Add console output
   logger.addOutput(std::make_shared<std::ostream>(std::cout.rdbuf()), LogLevel::DEBUG);

   // Enable asynchronous logging
   logger.enableAsynchronousLogging(true);
   ```

3. **Log Messages**

   ```cpp
   LOG_INFO("network", {"init"}, []() { return "Network initialized successfully."; });
   LOG_DEBUG("database", {"connection"}, []() { return "Database connection established."; });
   LOG_WARNING("network", {"latency"}, []() { return "Network latency is high."; });
   LOG_ERROR("database", {"query"}, []() { return "Failed to execute query."; });
   LOG_CRITICAL("system", {"memory"}, []() { return "Out of memory!"; });
   ```

4. **Shutdown the Logger**

   ```cpp
   // Flush and shutdown the logger
   logger.flush();
   logger.enableAsynchronousLogging(false);
   ```

---

## Features

- **Multiple Log Levels**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`, `OFF`
- **Timestamping**: Includes timestamps with customizable formats
- **ANSI Color Coding**: Color-coded messages based on severity level
- **Structured Formatting**: Supports plain text and JSON formats
- **Conditional Logging**: Logs messages based on the set log level
- **Output Control**: Redirect logs to multiple `std::ostream` instances
- **Logging Categories and Tags**: Organize logs by categories and tags
- **Asynchronous Logging**: Non-blocking logging suitable for multi-threaded applications
- **Custom Timestamp Format**: Use custom formats for timestamps
- **Source Location Metadata**: Includes file name, line number, and function name
- **Profiling and Benchmarking**: Measure execution time with timers
- **Configuration File Support**: Configure logger via external JSON file
- **Memory Safety**: Designed with smart pointers and RAII to prevent memory issues
- **Thread Safety**: Safe to use in multi-threaded applications
- **Header-only Design**: Easy integration without separate compilation

---

## Feature Examples

### Multiple Log Levels

Control the verbosity of your logs by setting the appropriate log level.

```cpp
logger.setGlobalLogLevel(LogLevel::WARNING);
```

Now, only `WARNING`, `ERROR`, and `CRITICAL` messages will be logged.

### Timestamping

Each log message includes a timestamp for better traceability.

**Output Example:**

```
2023-10-30 14:23:15 [INFO] [network] Network initialized successfully.
```

### ANSI Color Coding

Enable or disable ANSI color codes for log messages.

```cpp
logger.enableANSIColors(true);
```

**Color Codes:**

- `DEBUG`: Cyan
- `INFO`: Green
- `WARNING`: Yellow
- `ERROR`: Red
- `CRITICAL`: Red background

### Structured Formatting

Choose between plain text and JSON output formats.

```cpp
logger.setOutputFormat("json");
```

**JSON Output Example:**

```json
{
  "timestamp": "2023-10-30 14:23:15",
  "level": "INFO",
  "category": "network",
  "message": "Network initialized successfully.",
  "file": "main.cpp",
  "line": 42,
  "function": "main",
  "tags": ["init"]
}
```

### Conditional Logging

Messages below the set log level are not logged, minimizing performance overhead.

```cpp
// This won't be logged if the global log level is set to WARNING
LOG_DEBUG("database", {"debug"}, []() { return "This is a debug message."; });
```

### Output Control

Redirect logs to multiple outputs, such as files and console.

```cpp
// Add file output
auto fileStream = std::make_shared<std::ofstream>("app.log", std::ios::app);
if (fileStream->is_open()) {
    logger.addOutput(fileStream, LogLevel::DEBUG);
}
```

### Logging Categories and Tags

Organize and filter logs by categories and tags.

```cpp
logger.addCategory("authentication");
logger.addTag("security");

LOG_INFO("authentication", {"security"}, []() { return "User login successful."; });
```

### Asynchronous Logging

Enable asynchronous logging to improve performance in multi-threaded applications.

```cpp
logger.enableAsynchronousLogging(true);
```

### Custom Timestamp Format

Set a custom format for timestamps.

```cpp
logger.setTimestampFormat("%d-%m-%Y %H:%M:%S");
```

**Output Example:**

```
30-10-2023 14:23:15 [INFO] [network] Network initialized successfully.
```

### Source Location Metadata

Include file name, line number, and function name in log messages.

```cpp
LOG_ERROR("database", {"query"}, []() { return "Failed to execute query."; });
```

**Output Example:**

```
2023-10-30 14:23:15 [ERROR] [database] Failed to execute query. (main.cpp:45 in main)
```

### Profiling and Benchmarking

Measure the execution time of code blocks.

```cpp
START_TIMER("database_query");
// Execute database query
END_TIMER("database_query", LogLevel::INFO, "performance", {"benchmark"});
```

**Output Example:**

```
2023-10-30 14:23:15 [INFO] [performance] Timer [database_query] elapsed time: 120 ms
```

### Configuration File Support

Configure the logger via an external JSON file.

**config.json**

```json
{
  "globalLogLevel": "DEBUG",
  "outputs": [
    {
      "type": "console",
      "logLevel": "INFO",
      "timestampFormat": "%Y-%m-%d %H:%M:%S",
      "outputFormat": "plain",
      "useANSIColors": true
    },
    {
      "type": "file",
      "filePath": "app.log",
      "logLevel": "DEBUG",
      "timestampFormat": "%Y-%m-%d %H:%M:%S",
      "outputFormat": "json",
      "useANSIColors": false
    }
  ]
}
```

**Load Configuration**

```cpp
logger.loadConfiguration("config.json");
```

---

## Advanced Examples

### Example 1: Multi-Output and Custom Formatting

```cpp
#include "Logger.hpp"
#include <fstream>

int main() {
    using namespace LoggerNS;
    Logger& logger = Logger::getInstance();

    // Add console output with INFO level
    logger.addOutput(std::make_shared<std::ostream>(std::cout.rdbuf()), LogLevel::INFO);

    // Add file output with DEBUG level
    auto fileStream = std::make_shared<std::ofstream>("app.log", std::ios::app);
    if (fileStream->is_open()) {
        logger.addOutput(fileStream, LogLevel::DEBUG, "%d-%m-%Y %H:%M:%S", "json", false);
    }

    // Set global log level to DEBUG
    logger.setGlobalLogLevel(LogLevel::DEBUG);

    // Enable asynchronous logging
    logger.enableAsynchronousLogging(true);

    // Log messages
    LOG_DEBUG("system", {"init"}, []() { return "System initialized."; });
    LOG_INFO("network", {"connection"}, []() { return "Network connected."; });

    // Shutdown the logger
    logger.flush();
    logger.enableAsynchronousLogging(false);

    return 0;
}
```

### Example 2: Tag-Based Filtering

```cpp
#include "Logger.hpp"

int main() {
    using namespace LoggerNS;
    Logger& logger = Logger::getInstance();

    // Add console output
    logger.addOutput(std::make_shared<std::ostream>(std::cout.rdbuf()), LogLevel::INFO);

    // Add tags to filter
    logger.addTag("critical");

    LOG_INFO("system", {"status"}, []() { return "System running smoothly."; }); // Not logged
    LOG_CRITICAL("system", {"critical"}, []() { return "Critical system failure!"; }); // Logged

    return 0;
}
```

### Example 3: Asynchronous Logging in Multi-threaded Environment

```cpp
#include "Logger.hpp"
#include <thread>

void threadFunction(const std::string& threadName) {
    for (int i = 0; i < 10; ++i) {
        LOG_INFO("thread", {threadName}, [i, threadName]() {
            return "Message " + std::to_string(i) + " from " + threadName;
        });
    }
}

int main() {
    using namespace LoggerNS;
    Logger& logger = Logger::getInstance();

    // Add console output
    logger.addOutput(std::make_shared<std::ostream>(std::cout.rdbuf()), LogLevel::INFO);

    // Enable asynchronous logging
    logger.enableAsynchronousLogging(true);

    // Start threads
    std::thread t1(threadFunction, "Thread1");
    std::thread t2(threadFunction, "Thread2");

    t1.join();
    t2.join();

    // Shutdown the logger
    logger.flush();
    logger.enableAsynchronousLogging(false);

    return 0;
}
```

---

## Memory Safety Guidelines

The logger is designed with memory safety in mind, using smart pointers and RAII (Resource Acquisition Is Initialization) principles to manage resources automatically. However, it's important to follow certain guidelines to ensure memory safety while using the logger:

1. **Use Smart Pointers for Streams**

   - When adding outputs, use `std::shared_ptr` or `std::unique_ptr` to manage stream lifetimes.
   - **Example:**

     ```cpp
     auto fileStream = std::make_shared<std::ofstream>("app.log", std::ios::app);
     if (fileStream->is_open()) {
         logger.addOutput(fileStream, LogLevel::DEBUG);
     }
     ```

2. **Avoid Raw Pointers**

   - Do not use raw pointers for dynamic memory allocation. Rely on smart pointers provided by the logger.

3. **Thread Safety**

   - The logger is thread-safe, but ensure that any data passed to the logger is also managed safely.
   - When using tags or categories, ensure they are valid and not modified concurrently.

4. **Exception Safety**

   - The `messageGenerator` function in logging calls should handle exceptions internally if necessary.
   - The logger catches exceptions thrown during message generation to prevent crashes.

   **Example:**

   ```cpp
   LOG_INFO("system", {"init"}, []() {
       try {
           // Generate message
           return "System initialized.";
       } catch (...) {
           return "Error generating message.";
       }
   });
   ```

5. **Proper Shutdown**

   - Always flush and properly shut down the logger before application exit to ensure all messages are processed.

   ```cpp
   logger.flush();
   logger.enableAsynchronousLogging(false);
   ```

6. **Avoid Modifying Logger After Shutdown**

   - Do not attempt to log messages or modify logger settings after shutting down asynchronous logging.

7. **Use of RAII**

   - Rely on RAII patterns for resource management in your application to complement the logger's design.

8. **Avoid Long Blocking Operations in Message Generators**

   - Since message generators are executed within the logger, avoid long-running operations that could block logging threads.

---

## Contributing

This project is open to contributions! If you have ideas for new features, optimizations, or improvements, feel free to:

- Fork the repository
- Create a new branch
- Implement your feature
- Submit a pull request

**Example of Adding a New Feature:**

Suppose you want to add support for logging to a remote server. You could:

- Add a new method `logger.addRemoteOutput(const std::string& url);`
- Implement a new `Output` subclass to handle network communication
- Update the documentation accordingly

---

## Available Methods

| Method                                           | Description                                       |
|--------------------------------------------------|---------------------------------------------------|
| `Logger::getInstance()`                          | Retrieves the singleton instance of the logger    |
| `addOutput(std::shared_ptr<std::ostream>, LogLevel, ...)` | Adds a new output destination           |
| `setGlobalLogLevel(LogLevel level)`              | Sets the global log level                         |
| `setCategoryLogLevel(const std::string&, LogLevel)` | Sets log level for a specific category        |
| `addCategory(const std::string& category)`       | Adds a category to filter logs                    |
| `removeCategory(const std::string& category)`    | Removes a category from the filter                |
| `addTag(const std::string& tag)`                 | Adds a tag to filter logs                         |
| `removeTag(const std::string& tag)`              | Removes a tag from the filter                     |
| `setTimestampFormat(const std::string& format)`  | Sets the format for timestamps                    |
| `setOutputFormat(const std::string& format)`     | Sets the output format ("plain" or "json")        |
| `enableAsynchronousLogging(bool enable)`         | Enables or disables asynchronous logging          |
| `flush()`                                        | Flushes all pending log messages                  |
| `loadConfiguration(const std::string& path)`     | Loads configuration from a JSON file              |
| `startTimer(const std::string& timerName)`       | Starts a timer with the given name                |
| `endTimer(const std::string&, LogLevel, const std::string&, const std::set<std::string>&)` | Ends a timer and logs the elapsed time |

**Convenience Macros:**

- `LOG_DEBUG(category, tags, message)`
- `LOG_INFO(category, tags, message)`
- `LOG_WARNING(category, tags, message)`
- `LOG_ERROR(category, tags, message)`
- `LOG_CRITICAL(category, tags, message)`
- `START_TIMER(timerName)`
- `END_TIMER(timerName, level, category, tags)`

---

## Disclaimer

This logging utility is designed to provide a standardized and memory-safe logging mechanism for personal projects. It may not be the most efficient or feature-rich solution available. The primary goal is to simplify logging across different projects without having to implement a new system each time.

---

## License

This project is licensed under the MIT License.

---

Feel free to customize and adapt this logger to suit your project's needs!
