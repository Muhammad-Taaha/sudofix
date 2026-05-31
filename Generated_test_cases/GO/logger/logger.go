package logger

import (
	"fmt"
	"os"
	"time"
)

type Logger struct {
	file    *os.File
	maxSize int64
	curSize int64
}

func New(filename string, maxSize int64) *Logger {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return &Logger{}
	}
	info, _ := f.Stat()
	return &Logger{
		file:    f,
		maxSize: maxSize,
		curSize: info.Size(),
	}
}

func (l *Logger) Log(msg string) {
	if l.file == nil {
		return
	}
	line := fmt.Sprintf("%s %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
	n, _ := l.file.WriteString(line)
	l.curSize += int64(n)
	if l.curSize >= l.maxSize {
		l.file.Close()
		os.Rename(l.file.Name(), l.file.Name()+".old")
		f, _ := os.OpenFile(l.file.Name(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		l.file = f
		l.curSize = 0
	}
}