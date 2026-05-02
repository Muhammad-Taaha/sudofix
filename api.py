"""
REST API for Repo-LLM Backend
Main entry point for code parsing, analysis, and generation operations.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict
import os
from pathlib import Path
import traceback

from controllers.repo_scanner import RepoScanner
from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager
from cli_agent.cli_agent import CliAgent
from vector_store.store import VectorStore
from repo_loader.loader import RepoLoader

# ================================
# Pydantic Models
# ================================

class ParseRequest(BaseModel):
    """Request to parse a repository"""
    repo_path: str
    repo_url: Optional[str] = None
    branch: Optional[str] = "main"

class ParseResponse(BaseModel):
    """Response with parsing results"""
    repo_id: int
    total_chunks: int
    files_processed: int
    message: str

class QueryRequest(BaseModel):
    """RAG query request"""
    query: str
    top_k: int = 5

class QueryResult(BaseModel):
    """Individual query result"""
    file_name: str
    symbol: Optional[str] = None
    start_line: int
    end_line: int
    content: str
    similarity_score: Optional[float] = None

class QueryResponse(BaseModel):
    """Query response with results"""
    query: str
    results: List[QueryResult]
    total_results: int

class AnalysisRequest(BaseModel):
    """Request for code analysis (review/tests/docs)"""
    repo_path: str
    command: str  # "review", "test", or "doc"
    file_pattern: Optional[str] = None  # e.g., "*.py"

class AnalysisResponse(BaseModel):
    """Analysis operation response"""
    operation_id: str
    command: str
    status: str  # "pending", "processing", "completed", "error"
    message: str

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    db_connected: bool
    redis_connected: bool
    vector_store_ready: bool


# ================================
# FastAPI App Setup
# ================================

app = FastAPI(
    title="Repo-LLM API",
    description="Backend API for code parsing, analysis, and LLM generation",
    version="0.1.0"
)

# Initialize controllers
db = Postgres()
cache = RedisManager()
vector_store = VectorStore()
agent = None  # Will be initialized per request


# ================================
# Health & Status Endpoints
# ================================

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Check system health and connectivity"""
    db_conn = db.connect()
    redis_client = cache.connect()
    
    try:
        # Try to load vector store
        vector_store.load("vector_store")
        vector_ready = True
    except:
        vector_ready = False
    
    return HealthResponse(
        status="healthy" if db_conn and redis_client else "degraded",
        db_connected=db_conn is not None,
        redis_connected=redis_client is not None,
        vector_store_ready=vector_ready
    )


# ================================
# Parsing Endpoints
# ================================

@app.post("/parse", response_model=ParseResponse)
async def parse_repository(request: ParseRequest):
    """
    Parse a repository and chunk it.
    Can accept local path or clone from Git URL.
    """
    try:
        # Load the repository
        if request.repo_url:
            loader = RepoLoader(
                repo_url=request.repo_url,
                branch=request.branch
            )
            repo_path = loader.load()
        else:
            repo_path = request.repo_path
        
        if not Path(repo_path).exists():
            raise FileNotFoundError(f"Repository not found: {repo_path}")
        
        # Save to database
        repo_name = Path(repo_path).name
        repo_data = db.save_repository(repo_name, repo_path)
        repo_id = repo_data[0]['id']
        
        # Scan and parse files
        scanner = RepoScanner(repo_path)
        chunks = scanner.local_scanner()
        
        if not chunks:
            return ParseResponse(
                repo_id=repo_id,
                total_chunks=0,
                files_processed=0,
                message="No parseable files found in repository"
            )
        
        # Process chunks
        unique_files = set(chunk.get('file_path') for chunk in chunks)
        
        return ParseResponse(
            repo_id=repo_id,
            total_chunks=len(chunks),
            files_processed=len(unique_files),
            message=f"Successfully parsed {len(unique_files)} files into {len(chunks)} chunks"
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {str(e)}")


# ================================
# RAG Query Endpoints
# ================================

@app.post("/query", response_model=QueryResponse)
async def query_codebase(request: QueryRequest):
    """
    Query the vector store for relevant code chunks using RAG.
    """
    try:
        # Load vector store
        try:
            vector_store.load("vector_store")
        except:
            raise HTTPException(
                status_code=503, 
                detail="Vector store not initialized. Please parse a repository first."
            )
        
        # Query
        results = vector_store.query(request.query, top_k=request.top_k)
        
        # Format results
        formatted_results = []
        for result in results:
            formatted_results.append(QueryResult(
                file_name=result.get('file_name', 'unknown'),
                symbol=result.get('symbol'),
                start_line=result.get('start_line', 0),
                end_line=result.get('end_line', 0),
                content=result.get('content', ''),
                similarity_score=result.get('similarity_score')
            ))
        
        return QueryResponse(
            query=request.query,
            results=formatted_results,
            total_results=len(formatted_results)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query error: {str(e)}")


# ================================
# Analysis Endpoints
# ================================

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_code(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    Trigger code analysis operation (review/test/doc generation).
    Returns immediately with operation ID.
    """
    if request.command not in ["review", "test", "doc"]:
        raise HTTPException(
            status_code=400,
            detail="Command must be 'review', 'test', or 'doc'"
        )
    
    if not Path(request.repo_path).exists():
        raise HTTPException(status_code=404, detail="Repository path not found")
    
    try:
        operation_id = f"{request.command}_{hash(request.repo_path)}"
        
        # Queue background task
        background_tasks.add_task(
            _run_analysis_task,
            repo_path=request.repo_path,
            command=request.command,
            operation_id=operation_id
        )
        
        return AnalysisResponse(
            operation_id=operation_id,
            command=request.command,
            status="pending",
            message=f"Analysis task queued: {request.command}"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")


async def _run_analysis_task(repo_path: str, command: str, operation_id: str):
    """Background task to run code analysis"""
    try:
        # Initialize agent
        agent = CliAgent(repo_path, command)
        
        # Scan repository
        scanner = RepoScanner(repo_path)
        chunks = scanner.local_scanner()
        
        if not chunks:
            return
        
        # Process each chunk
        for i, chunk in enumerate(chunks):
            try:
                if command == "review":
                    result = agent.review_code(chunk)
                elif command == "test":
                    result = agent.generate_test(chunk)
                elif command == "doc":
                    result = agent.generate_documentation(chunk)
                
                # Store in cache
                if result:
                    cache.caching_the_response(chunk.get('content', ''), result)
                    
            except Exception as chunk_err:
                print(f"Error processing chunk {i}: {chunk_err}")
                continue
        
        # Mark as completed in cache
        cache.save_to_reddis(f"operation:{operation_id}", "completed")
        
    except Exception as e:
        print(f"Background task error: {e}")
        cache.save_to_reddis(f"operation:{operation_id}", f"error:{str(e)}")


@app.get("/analyze/{operation_id}")
async def get_analysis_status(operation_id: str):
    """Check status of an analysis operation"""
    try:
        redis_client = cache.connect()
        status = redis_client.get(f"operation:{operation_id}")
        
        if status:
            status_str = status.decode() if isinstance(status, bytes) else status
            return {
                "operation_id": operation_id,
                "status": status_str
            }
        else:
            raise HTTPException(status_code=404, detail="Operation not found")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check error: {str(e)}")


# ================================
# Info Endpoints
# ================================

@app.get("/info")
async def get_system_info():
    """Get system information and capabilities"""
    return {
        "name": "Repo-LLM Backend",
        "version": "0.1.0",
        "capabilities": {
            "parsing": ["python", "markdown", "sql", "generic"],
            "analysis": ["review", "test", "doc"],
            "storage": ["postgres", "redis", "faiss"]
        },
        "endpoints": {
            "health": "GET /health",
            "parse": "POST /parse",
            "query": "POST /query",
            "analyze": "POST /analyze",
            "status": "GET /analyze/{operation_id}"
        }
    }


# ================================
# Error Handling
# ================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail}
    )


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("API_PORT", 8000))
    host = os.getenv("API_HOST", "0.0.0.0")
    
    print(f"🚀 Starting Repo-LLM API on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
