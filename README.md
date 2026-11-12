# PromptShield: Injection and PII Firewall for RAG Apps

A local security layer for RAG apps. It blocks prompt-injection attacks (including ones hidden
inside uploaded documents), masks personal data (Indian PII formats), and checks answers for
leaks. Everything runs offline with Ollama and ChromaDB.

## Demo
![Poisoned file quarantined](screenshots/quarantine.png)
![System prompt blocked](screenshots/blocked_prompt.png)

## Why
RAG apps trust the documents they read, so a hidden line like "ignore previous instructions"
can hijack the model, and private data can leak into answers. PromptShield adds guards and,
more importantly, measures how well they work.

## How it works
Part 1, upload: file -> extract text -> split into chunks -> document guard -> embed -> ChromaDB
(suspicious chunks are quarantined and logged; PII is masked before storage).

Part 2, ask: question -> input guard -> retrieve top chunks -> Ollama (llama3.1) -> output guard -> answer.

Guards:
1. Regex rules for known attack phrases
2. A small LLM judge (llama3.2) as a second opinion
3. PII masking: phone, email, Aadhaar, PAN
4. Canary secret in the system prompt to detect leaks
5. JSON-lines security log

## Tech stack
Python, Streamlit, Ollama (llama3.1, llama3.2, nomic-embed-text), ChromaDB, pypdf, Docker

## Quick start (local)
```bash
ollama pull llama3.1
ollama pull llama3.2
ollama pull nomic-embed-text
pip install -r requirements.txt
streamlit run app.py
```
Open http://localhost:8501

## Run with Docker
Ollama must be running on your machine.
```bash
docker compose up --build
```

## Evaluation
```bash
python evaluate.py
```
The suite runs 12 direct attacks, 2 poisoned documents and 5 normal questions, with and
without the shield. Success is detected with marker strings and a planted canary secret.

Paste your own results here (from results.md):

| Setup | Attacks succeeded | Attack success rate | Normal questions blocked | Clean chunks quarantined |
|---|---|---|---|---|
| Plain RAG | | | | |
| PromptShield | | | | |

## Tests
```bash
pip install pytest
pytest
```

## Limitations
- Regex rules miss new attack styles; the LLM judge can give false alarms.
- A small test-suite (about 14 attacks) is not proof of safety.
- Masking PII in documents protects privacy but also hides contact details from answers.
- A quarantined chunk removes all text in that chunk, including useful text.
- The vector store and shield are tuned for English text.

## Future work
- Grow the attack set to 30+ prompts and more document types
- Persistent audit dashboard
- Compare more judge models