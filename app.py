from dotenv import load_dotenv

load_dotenv()

from pkpl_group.app import app


if __name__ == "__main__":
    app.start(host="0.0.0.0", port=8080)
