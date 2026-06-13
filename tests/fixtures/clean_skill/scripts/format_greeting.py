import sys


def format_greeting(name: str) -> str:
    return f"Hello, {name}!"


if __name__ == "__main__":
    print(format_greeting(sys.argv[1] if len(sys.argv) > 1 else "world"))
