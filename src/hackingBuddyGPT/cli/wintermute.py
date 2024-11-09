import argparse
import sys
from hackingBuddyGPT.usecases.base import use_cases
from hackingBuddyGPT.utils.console.console import Console

def main():
    # Initialize the console and display the logo
    console = Console()
    console.display_logo()

    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(required=True)
    for name, use_case in use_cases.items():
        use_case.build_parser(subparser.add_parser(
            name=use_case.name,
            help=use_case.description
        ))

    parsed = parser.parse_args(sys.argv[1:])
    instance = parsed.use_case(parsed)
    instance.init()
    instance.run()

if __name__ == "__main__":
    main()
