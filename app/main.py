import os

from dotenv import load_dotenv

load_dotenv()

token = os.getenv("GITHUB_TOKEN")

if __name__ == "__main__":
    print("Hello World!")
    print("Token:", token)
