package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"deepvulnengine/config"
	"deepvulnengine/pool"
	"deepvulnengine/jobs"
	"deepvulnengine/cleaner"
	"deepvulnengine/pipeline"
	"deepvulnengine/handler"
	"deepvulnengine/leak"
	"deepvulnengine/logger"
	"deepvulnengine/server"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config.json>\n", os.Args[0])
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var cfg config.AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}

	log := logger.New(cfg.LogFile, 1024*1024)
	memPool := pool.NewMemoryPool(cfg.PoolSize)
	tp := NewThreadPool(4)
	jm := jobs.NewJobManager()
	srv := server.NewHttpServer(cfg.Port, memPool)
	go srv.Start()

	var wg sync.WaitGroup
	for _, job := range cfg.Jobs {
		wg.Add(1)
		job := job // capture
		switch job.Type {
		case "transform":
			tp.Submit(func() {
				defer wg.Done()
				len := int64(len(job.Pattern))
				if len == 0 {
					len = 1
				}
				buf := memPool.AllocBuffer(len, job.Multiplier, 1)
				if buf == nil {
					log.Log("Transform allocation failed")
					return
				}
				// copy pattern into buffer
				cbuf := buf.Bytes()
				for i := int64(0); i < job.Multiplier; i++ {
					copy(cbuf[i*len:], job.Pattern)
				}
				log.Log(fmt.Sprintf("Transformed: %s", string(cbuf)))
				memPool.Free(buf)
			})
		case "data_manage":
			tp.Submit(func() {
				defer wg.Done()
				for _, chunk := range job.DataChunks {
					jm.AddData(chunk)
				}
				if job.ScheduleCleanupAt < jm.DataCount() {
					jm.ScheduleCleanup(job.ScheduleCleanupAt)
				}
				for i := 0; i < 1000; i++ {
					jm.AddData(fmt.Sprintf("padding %d", i))
				}
				jm.RunCleanup()
			})
		case "cleanup_dir":
			tp.Submit(func() {
				defer wg.Done()
				cleaner.RecursiveDelete(job.Dir)
			})
		case "pipeline":
			tp.Submit(func() {
				defer wg.Done()
				out := pipeline.Execute(job.Cmd, job.Pattern)
				log.Log("Pipeline output: " + out)
			})
		case "process_files":
			tp.Submit(func() {
				defer wg.Done()
				handler.ProcessFiles(job.File1, job.File2)
			})
		case "log_leak":
			tp.Submit(func() {
				defer wg.Done()
				leak.WriteLeakyLog("leak_log.bin", 1, "sensitive data")
			})
		default:
			wg.Done()
		}
	}
	wg.Wait()
	srv.Stop()
}