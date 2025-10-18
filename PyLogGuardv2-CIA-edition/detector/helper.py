import argparse

DEFAULT_THRESHOLD = 10
DEFAULT_WINDOW_MINUTES = 5

def build_base_parser(desc: str):
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help="Minimum attempts/packets to consider suspicious")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_MINUTES,
                        help="Time window in minutes")
    parser.add_argument("--created-by", type=int, default=None,
                        help="Optional user_id who runs detector")
    parser.add_argument("--debug", action="store_true",
                        help="Show debug information (query counts etc.)")
    return parser