"""Streamlit page: upload a document, then chat with it. The shield can be switched on or off."""
import streamlit as st

import config
import rag
import shield

COLLECTION = "docs"

st.set_page_config(page_title="PromptShield", layout="centered")
st.title("PromptShield")
st.caption("Injection and PII firewall for a local RAG app (Ollama + ChromaDB)")

missing = config.missing_models()
if missing is None:
    st.error(f"Cannot reach Ollama at {config.OLLAMA_HOST}. Start the Ollama app and refresh.")
    st.stop()
if missing:
    st.error("Some models are missing. Run these in a terminal, then refresh:")
    st.code("\n".join(f"ollama pull {m}" for m in missing))
    st.stop()

# ---------- sidebar ----------
with st.sidebar:
    st.header("Settings")
    shield_on = st.toggle("PromptShield ON", value=True)
    deep = st.toggle("Deep scan with LLM (slower)", value=True)
    st.write(f"Chunks stored: {rag.count(COLLECTION)}")
    if st.button("Clear knowledge base"):
        rag.reset_collection(COLLECTION)
        st.session_state.messages = []
        st.rerun()

# ---------- Part 1: upload ----------
st.subheader("1. Upload a document")
uploaded = st.file_uploader("PDF or TXT", type=["pdf", "txt"])
if uploaded and st.button("Process document"):
    with st.spinner("Scanning and indexing..."):
        text = rag.extract_text(uploaded, uploaded.name)
        stats = rag.ingest_text(text, uploaded.name, COLLECTION, use_shield=shield_on, deep=deep)
    st.success(f"Stored {stats['stored']} of {stats['total']} chunks.")
    if stats["quarantined"]:
        st.warning(f"{len(stats['quarantined'])} suspicious chunk(s) were quarantined and not stored.")
        with st.expander("See quarantined chunks"):
            for item in stats["quarantined"]:
                st.write(f"**Reason:** {item['reason']}")
                st.code(item["chunk"])

# ---------- Part 2: chat ----------
st.subheader("2. Ask questions")
if "messages" not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

with st.expander("Security log (last 20 events)"):
    events = shield.read_log(20)
    if events:
        st.dataframe(events[::-1])
    else:
        st.write("No events yet.")

if question := st.chat_input("Ask about your document"):
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            result = rag.answer_question(question, COLLECTION, use_shield=shield_on, deep=deep)
        st.markdown(result["answer"])
        if result["blocked"]:
            st.warning(f"Blocked by PromptShield: {result['reason']}")
    st.session_state.messages.append({"role": "assistant", "content": result["answer"]})