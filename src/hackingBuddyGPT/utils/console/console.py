from rich import console as rich_console
from art import text2art
from hackingBuddyGPT.utils.configurable import configurable

@configurable("console", "Console")
class Console(rich_console.Console):
    """
    Simple wrapper around the rich Console class, to allow for dependency injection and configuration.
    """
    def __init__(self):
        super().__init__()

    def display_logo(self):
        # Create ASCII art logo with a retro slant font and orange-like color
        logo_text = text2art("Herbie-P", font="slant")  # Slanted for a retro 80s vibe
        self.print(logo_text, style="bold bright_yellow")  # Using bright yellow for an orange-like effect
