from controllers.data_base_controller import Postgres
from controllers.reddis_controller import RedisManager


def run_llm(repo_path: str):
    #database
    db=Postgres()
    connection = db.connect()
    if not connection :
        return "error occured in the initialization of the database"
    #reddis 
    cache = RedisManager()
    redis_client = cache.connect()
    if not redis_client:
        return "Cannot proceed without Redis connection"
        
    

if __name__ == "__main__":
    # Change this path to the repo you want to scan
    repo_path = "./my_project_repo"
    run_llm(repo_path)