#!/usr/bin/python3

import argparse
from hackingBuddyGPT.utils.db_storage import DbStorage
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from art import text2art

# helper to fill the history table with data from the db
def get_history_table(run_id: int, db: DbStorage, round: int) -> Table:
    table = Table(title="Executed Command History", show_header=True, show_lines=True)
    table.add_column("ThinkTime", style="dim")
    table.add_column("Tokens", style="dim")
    table.add_column("Cmd")
    table.add_column("Resp. Size", justify="right")

    for i in range(0, round+1):
        table.add_row(*db.get_round_data(run_id, i))

    return table

def display_logo(console):
    # Create ASCII art logo with a retro slant font and orange-like color
    logo_text = text2art("Herbie-P", font="slant")  # Slanted for a retro 80s vibe
    console.print(logo_text, style="bold bright_yellow")  # Using bright yellow for an orange-like effect



def main():
    # setup infrastructure for outputting information
    console = Console()
    display_logo(console)

    parser = argparse.ArgumentParser(description='View an existing log file.')
    parser.add_argument('log', type=str, help='sqlite3 db for reading log data')
    args = parser.parse_args()

    # setup in-memory/persistent storage for command history
    db = DbStorage(args.log)
    try:
        db.connect()
        db.setup_db()
    except Exception as e:
        console.log(f"Error setting up database: {e}")
        exit(1)

    # setup round meta-data
    run_id: int = 1

    with Progress(console=console) as progress:
        while True:
            run = db.get_run_data(run_id)
            if run is None:
                break

            if run[4] is None:
                console.print(Panel(f"run: {run[0]}/{run[1]}\ntest: {run[2]}\nresult: {run[3]}", title="Run Data"))
            else:
                console.print(Panel(f"run: {run[0]}/{run[1]}\ntest: {run[2]}\nresult: {run[3]} after {run[4]} rounds", title="Run Data"))
            
            # Display round history
            if run[4] is not None:
                console.print(get_history_table(run_id, db, run[4] - 1))

            run_id += 1

if __name__ == "__main__":
    main()
