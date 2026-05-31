package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"deepvulnengine/pool"
)

type HttpServer struct {
	port int
	pool *pool.MemoryPool
	srv  *http.Server
}

func NewHttpServer(port int, p *pool.MemoryPool) *HttpServer {
	return &HttpServer{port: port, pool: p}
}

func (hs *HttpServer) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		used := hs.pool.UsedMemory() // VULN-4: unsynchronized read (race)
		resp := map[string]int64{"pool_usage": used}
		js, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	})
	hs.srv = &http.Server{Addr: ":" + strconv.Itoa(hs.port), Handler: mux}
	hs.srv.ListenAndServe()
}

func (hs *HttpServer) Stop() {
	if hs.srv != nil {
		hs.srv.Close()
	}
}