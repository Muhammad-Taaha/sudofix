"""
REST API for Repo-LLM Backend
Main entry point for code parsing, analysis, and generation operations.
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Header, Request
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
from git_controller.github_webhook_handler import GitHubWebhookHandler

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
webhook_handler = GitHubWebhookHandler(webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET"))
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


# ================================
# Operation Status Endpoints
# ================================

class OperationStatusResponse(BaseModel):
    """Operation status response"""
    operation_id: str
    status: str
    message: str

@app.get("/operations/{operation_id}", response_model=OperationStatusResponse)
async def get_operation_status(operation_id: str):
    """Get the status of an analysis operation"""
    try:
        redis_client = cache.connect()
        if not redis_client:
            raise HTTPException(status_code=503, detail="Cache service unavailable")
        
        status_key = f"operation:{operation_id}"
        status = redis_client.get(status_key)
        
        if status is None:
            return OperationStatusResponse(
                operation_id=operation_id,
                status="not_found",
                message="Operation not found or expired"
            )
        
        status_str = status.decode() if isinstance(status, bytes) else status
        
        if status_str.startswith("error:"):
            return OperationStatusResponse(
                operation_id=operation_id,
                status="error",
                message=status_str.replace("error:", "")
            )
        
        return OperationStatusResponse(
            operation_id=operation_id,
            status=status_str,
            message=f"Operation status: {status_str}"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check error: {str(e)}")


# ================================
# Repository Management Endpoints
# ================================

class RepositoryInfo(BaseModel):
    """Repository information"""
    id: int
    name: str
    path: str
    last_scanned: Optional[str] = None

@app.get("/repositories", response_model=List[RepositoryInfo])
async def list_repositories():
    """List all indexed repositories"""
    try:
        sql = "SELECT id, name, path, last_scanned FROM repositories ORDER BY id DESC"
        repos = db._execute_query(sql, fetch=True)
        
        return [
            RepositoryInfo(
                id=r['id'],
                name=r['name'],
                path=r['path'],
                last_scanned=str(r['last_scanned']) if r['last_scanned'] else None
            )
            for r in (repos or [])
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Repository listing error: {str(e)}")


@app.get("/repositories/{repo_id}", response_model=RepositoryInfo)
async def get_repository(repo_id: int):
    """Get information about a specific repository"""
    try:
        sql = "SELECT id, name, path, last_scanned FROM repositories WHERE id = %s"
        result = db._execute_query(sql, (repo_id,), fetch=True)
        
        if not result:
            raise HTTPException(status_code=404, detail="Repository not found")
        
        r = result[0]
        return RepositoryInfo(
            id=r['id'],
            name=r['name'],
            path=r['path'],
            last_scanned=str(r['last_scanned']) if r['last_scanned'] else None
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Repository retrieval error: {str(e)}")


@app.delete("/repositories/{repo_id}")
async def delete_repository(repo_id: int):
    """Delete a repository and all its associated data"""
    try:
        sql = "DELETE FROM repositories WHERE id = %s RETURNING id"
        result = db._execute_query(sql, (repo_id,), fetch=True)
        
        if not result:
            raise HTTPException(status_code=404, detail="Repository not found")
        
        return {"message": f"Repository {repo_id} deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Repository deletion error: {str(e)}")


# ================================
# Batch Analysis Endpoints
# ================================

class BatchAnalysisRequest(BaseModel):
    """Request for batch analysis across multiple repositories"""
    repo_ids: List[int]
    command: str  # "review", "test", or "doc"

class BatchAnalysisResponse(BaseModel):
    """Batch analysis response"""
    batch_id: str
    operation_ids: List[str]
    total_operations: int
    message: str

@app.post("/batch-analyze", response_model=BatchAnalysisResponse)
async def batch_analyze(request: BatchAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Trigger batch analysis across multiple repositories.
    Each repository gets its own operation ID.
    """
    if request.command not in ["review", "test", "doc"]:
        raise HTTPException(
            status_code=400,
            detail="Command must be 'review', 'test', or 'doc'"
        )
    
    if not request.repo_ids:
        raise HTTPException(status_code=400, detail="At least one repository ID required")
    
    try:
        import hashlib
        import time
        
        batch_id = hashlib.md5(f"{request.repo_ids}_{time.time()}".encode()).hexdigest()
        operation_ids = []
        
        # Queue analysis for each repository
        for repo_id in request.repo_ids:
            sql = "SELECT path FROM repositories WHERE id = %s"
            result = db._execute_query(sql, (repo_id,), fetch=True)
            
            if result:
                repo_path = result[0]['path']
                operation_id = f"{request.command}_{repo_id}_{batch_id}"
                operation_ids.append(operation_id)
                
                background_tasks.add_task(
                    _run_analysis_task,
                    repo_path=repo_path,
                    command=request.command,
                    operation_id=operation_id
                )
        
        return BatchAnalysisResponse(
            batch_id=batch_id,
            operation_ids=operation_ids,
            total_operations=len(operation_ids),
            message=f"Batch analysis queued for {len(operation_ids)} repositories"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch analysis error: {str(e)}")


# ================================
# Statistics & Insights Endpoints
# ================================

class CodeStatsResponse(BaseModel):
    """Code statistics response"""
    repo_id: int
    total_files: int
    total_chunks: int
    total_lines_of_code: int
    languages: Dict[str, int]

@app.get("/statistics/{repo_id}", response_model=CodeStatsResponse)
async def get_repository_statistics(repo_id: int):
    """Get code statistics for a repository"""
    try:
        # Get files count
        files_sql = "SELECT COUNT(*) as count FROM files WHERE repo_id = %s"
        files_result = db._execute_query(files_sql, (repo_id,), fetch=True)
        total_files = files_result[0]['count'] if files_result else 0
        
        # Get language distribution
        lang_sql = """
            SELECT language, COUNT(*) as count 
            FROM files 
            WHERE repo_id = %s 
            GROUP BY language
        """
        lang_result = db._execute_query(lang_sql, (repo_id,), fetch=True) or []
        languages = {r['language']: r['count'] for r in lang_result}
        
        # Get chunks count
        chunks_sql = """
            SELECT COUNT(*) as count 
            FROM chunks c
            JOIN code_entities ce ON c.code_entity_id = ce.id
            JOIN files f ON ce.file_id = f.id
            WHERE f.repo_id = %s
        """
        chunks_result = db._execute_query(chunks_sql, (repo_id,), fetch=True)
        total_chunks = chunks_result[0]['count'] if chunks_result else 0
        
        # Get total LOC
        loc_sql = """
            SELECT SUM(size) as total_loc
            FROM files
            WHERE repo_id = %s
        """
        loc_result = db._execute_query(loc_sql, (repo_id,), fetch=True)
        total_lines = loc_result[0]['total_loc'] if loc_result and loc_result[0]['total_loc'] else 0
        
        return CodeStatsResponse(
            repo_id=repo_id,
            total_files=total_files,
            total_chunks=total_chunks,
            total_lines_of_code=total_lines,
            languages=languages
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Statistics error: {str(e)}")


# ================================
# GitHub Webhook Endpoints
# ================================

class WebhookResponse(BaseModel):
    """Webhook processing response"""
    status: str
    event_type: str
    message: str
    changed_files_count: int

@app.post("/webhooks/github")
async def handle_github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    background_tasks: BackgroundTasks = None
):
    """
    Handle GitHub webhook events for push, PR, and releases.
    Validates signature and triggers incremental updates.
    """
    try:
        # Get raw body
        body = await request.body()
        
        # Validate signature
        if x_hub_signature_256:
            is_valid = webhook_handler.validate_signature(body, x_hub_signature_256)
            if not is_valid:
                raise HTTPException(status_code=401, detail="Invalid webhook signature")
        
        # Parse payload
        import json
        payload = json.loads(body.decode())
        
        # Parse webhook
        parsed = webhook_handler.parse_webhook(payload)
        if not parsed:
            raise HTTPException(status_code=400, detail="Unsupported webhook event")
        
        event_type = parsed.get("event_type", "unknown")
        repo_name = parsed.get("repository", "unknown")
        changed_files = webhook_handler.get_changed_files(payload, event_type)
        
        # Queue background processing
        if background_tasks and changed_files:
            background_tasks.add_task(
                _process_webhook_changes,
                repo_name=repo_name,
                event_type=event_type,
                changed_files=changed_files,
                webhook_data=parsed
            )
        
        return WebhookResponse(
            status="received",
            event_type=event_type,
            message=f"Webhook for {repo_name} processed successfully",
            changed_files_count=len(changed_files)
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Webhook processing error: {str(e)}")


async def _process_webhook_changes(
    repo_name: str,
    event_type: str,
    changed_files: List[str],
    webhook_data: Dict
):
    """
    Background task to process webhook changes.
    Incrementally re-parses changed files and marks entities for re-analysis.
    """
    try:
        print(f"🔔 Processing {event_type} webhook for {repo_name}")
        
        # Find repository in database
        sql = "SELECT id, path FROM repositories WHERE name LIKE %s LIMIT 1"
        repos = db._execute_query(sql, (f"%{repo_name}%",), fetch=True)
        
        if not repos:
            print(f"⚠️ Repository {repo_name} not found in database")
            return
        
        repo_id = repos[0]['id']
        repo_path = repos[0]['path']
        
        # Trigger incremental scan
        scanner = RepoScanner(repo_path)
        chunks = scanner.github_webhook_scanner(changed_files)
        
        if not chunks:
            print(f"ℹ️ No chunks found for {len(changed_files)} changed files")
            return
        
        # Process chunks
        files_processed = set()
        for chunk in chunks:
            file_path = chunk.get('file_path')
            if file_path:
                files_processed.add(file_path)
            
            # Mark entity as dirty for re-analysis
            chunk_hash = chunk.get('hash')
            if chunk_hash and db:
                try:
                    db.mark_entity_as_dirty(chunk_hash)
                except:
                    pass
        
        print(f"✅ Webhook processing complete: {len(files_processed)} files updated")
        
    except Exception as e:
        print(f"❌ Webhook processing error: {e}")


@app.get("/webhooks/github/info")
async def get_webhook_info():
    """Get GitHub webhook configuration information"""
    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    return {
        "webhook_url": "/webhooks/github",
        "events_supported": ["push", "pull_request", "release", "issues", "pull_request_review"],
        "webhook_secret_configured": bool(webhook_secret),
        "instructions": {
            "setup": "Configure in GitHub: Settings → Webhooks",
            "payload_url": "https://your-domain.com/webhooks/github",
            "content_type": "application/json",
            "events": ["push", "pull_request", "release"]
        }
    }


# Error Handlers
# ================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status": "error"}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "status": "error", "error": str(exc)}
    )


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
            "batch-analyze": "POST /batch-analyze",
            "webhooks": "POST /webhooks/github"
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("API_PORT", 8000))
    host = os.getenv("API_HOST", "0.0.0.0")
    
    print(f"🚀 Starting Repo-LLM API on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
