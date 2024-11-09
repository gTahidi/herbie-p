import argparse
import sys
import logging
from hackingBuddyGPT.utils.configurable import configurable, parameter
from hackingBuddyGPT.utils.db_storage.db_storage import DbStorage

# Configure logging to display on the console
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class Answer:
    def __init__(self, duration: float, tokens_query: int, tokens_response: int, prompt: str, answer: str):
        self.duration = duration
        self.tokens_query = tokens_query
        self.tokens_response = tokens_response
        self.prompt = prompt
        self.answer = answer

def test_db_storage():
    try:
        storage = DbStorage(connection_string="test_log_db.sqlite3")
        storage.init()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        return
    
    try:
        run_id = storage.create_new_run(model="TestModel", tag="TestTag")
        if run_id == -1:
            logger.error("Failed to create a new run.")
            return
        logger.info(f"Created new run with run_id: {run_id}")
    except Exception as e:
        logger.error(f"Error during run creation: {e}")
        return
    
    try:
        answer = Answer(duration=0.5, tokens_query=50, tokens_response=100, prompt="Test Prompt", answer="Test Answer")
        storage.add_log_query(run_id=run_id, round=1, cmd="exec_command whoami", result="bob", answer=answer)
        logger.info("Logged query successfully.")
    except Exception as e:
        logger.error(f"Error during logging query: {e}")
    
    try:
        overview = storage.get_log_overview()
        logger.info("Log Overview:")
        for run, data in overview.items():
            logger.info(f"Run ID: {run}, Data: {data}")
    except Exception as e:
        logger.error(f"Error retrieving log overview: {e}")
    
    try:
        # Properly close the connection using the class method
        storage.close()
        logger.info("Database connection closed successfully.")
    except Exception as e:
        logger.error(f"Error closing the database connection: {e}")

if __name__ == "__main__":
    test_db_storage()
