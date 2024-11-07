from hackingBuddyGPT.utils.db_storage import DbStorage

@dataclass
class Answer:
    duration: float
    tokens_query: int
    tokens_response: int
    prompt: str
    answer: str

def test_db_storage():
    storage = DbStorage(connection_string="test_log_db.sqlite3")
    storage.init()

    run_id = storage.create_new_run(model="TestModel", tag="TestTag")
    if run_id == -1:
        print("Failed to create a new run.")
        return

    answer = Answer(duration=0.5, tokens_query=50, tokens_response=100, prompt="Test Prompt", answer="Test Answer")
    storage.add_log_query(run_id=run_id, round=1, cmd="exec_command whoami", result="bob", answer=answer)
    
    overview = storage.get_log_overview()
    print("Log Overview:", overview)

    # Close the connection
    storage.close()

if __name__ == "__main__":
    test_db_storage()
