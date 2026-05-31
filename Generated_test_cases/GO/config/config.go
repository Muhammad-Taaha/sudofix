package config

type AppConfig struct {
	Port        int        `json:"port"`
	LogFile     string     `json:"log_file"`
	PoolSize    int64      `json:"pool_size"`
	Jobs        []JobConfig `json:"jobs"`
	CleanupDir  string     `json:"cleanup_dir"`
	PipelineCmd string     `json:"pipeline_cmd"`
}

type JobConfig struct {
	Type              string   `json:"type"`
	Pattern           string   `json:"pattern"`
	Multiplier        int64    `json:"multiplier"`
	Dir               string   `json:"dir"`
	Cmd               string   `json:"cmd"`
	File1             string   `json:"file1"`
	File2             string   `json:"file2"`
	DataChunks        []string `json:"data_chunks"`
	ScheduleCleanupAt int64    `json:"schedule_cleanup_at"`
}