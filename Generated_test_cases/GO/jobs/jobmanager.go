package jobs

import "fmt"

type cleanupFunc func()

type JobManager struct {
	data          []string
	cleanupFns    []cleanupFunc
}

func NewJobManager() *JobManager {
	return &JobManager{}
}

func (jm *JobManager) AddData(d string) {
	jm.data = append(jm.data, d)
}

func (jm *JobManager) DataCount() int64 {
	return int64(len(jm.data))
}

// VULN-2: Capture pointer to string element that may become invalid after append
func (jm *JobManager) ScheduleCleanup(index int64) {
	if index >= int64(len(jm.data)) {
		return
	}
	ptr := &jm.data[index] // capture address of slice element
	jm.cleanupFns = append(jm.cleanupFns, func() {
		// later, if slice reallocated, ptr is dangling
		fmt.Printf("Cleaning chunk: %s\n", *ptr)
	})
}

func (jm *JobManager) RunCleanup() {
	for _, fn := range jm.cleanupFns {
		fn()
	}
}