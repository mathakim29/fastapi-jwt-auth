uv venv
source .venv/bin/activate

uv pip install -r requirements.txt
uvicorn main:app --reload  > "logs/$(date +'%Y-%m-%d_%H-%M-%S').log" 2>&1
