package logger

import (
	"fmt"
	"log"
	"strings"
)

// Level constants
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

var (
	currentLevel = LevelInfo
	debugEnabled = false
)

// Init initializes the logger with the specified level
func Init(level string) {
	currentLevel = strings.ToLower(level)
	debugEnabled = currentLevel == LevelDebug

	// Set log flags: date + time
	log.SetFlags(log.Ldate | log.Ltime)

	// Set prefix based on level
	if debugEnabled {
		log.SetPrefix("[DEBUG] ")
	} else {
		log.SetPrefix("[INFO] ")
	}
}

// Debug logs a debug message (only printed when log level is debug)
func Debug(v ...interface{}) {
	if debugEnabled {
		log.Print("[DEBUG] ", fmt.Sprint(v...))
	}
}

// Debugf logs a debug message with format (only printed when log level is debug)
func Debugf(format string, v ...interface{}) {
	if debugEnabled {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// Info logs an info message
func Info(v ...interface{}) {
	log.Print("[INFO] ", fmt.Sprint(v...))
}

// Infof logs an info message with format
func Infof(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

// Warn logs a warning message
func Warn(v ...interface{}) {
	log.Print("[WARN] ", fmt.Sprint(v...))
}

// Warnf logs a warning message with format
func Warnf(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

// Error logs an error message
func Error(v ...interface{}) {
	log.Print("[ERROR] ", fmt.Sprint(v...))
}

// Errorf logs an error message with format
func Errorf(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

// Fatal logs a fatal message and exits
func Fatal(v ...interface{}) {
	log.Fatal("[FATAL] ", fmt.Sprint(v...))
}

// Fatalf logs a fatal message with format and exits
func Fatalf(format string, v ...interface{}) {
	log.Fatalf("[FATAL] "+format, v...)
}

// GetLevel returns the current log level
func GetLevel() string {
	return currentLevel
}

// IsDebug returns true if debug logging is enabled
func IsDebug() bool {
	return debugEnabled
}
