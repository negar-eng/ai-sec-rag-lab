from langchain_community.document_loaders import DirectoryLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_anthropic import ChatAnthropic
from dotenv import load_dotenv

load_dotenv()

print("Step 1: Loading documents...")
loader = DirectoryLoader("./docs", glob="**/*.txt")
docs = loader.load()
print(f"  Loaded {len(docs)} document(s)")

print("Step 2: Chunking...")
splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
chunks = splitter.split_documents(docs)
print(f"  Created {len(chunks)} chunks")

print("Step 3: Embedding locally (first run downloads model ~90MB)...")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

print("Step 4: Storing in Chroma...")
vectordb = Chroma.from_documents(chunks, embeddings, persist_directory="./chroma_db")
print("  Chroma DB saved to ./chroma_db")

print("Step 5: Setting up Claude...")
llm = ChatAnthropic(model="claude-haiku-4-5")

# Retrieve relevant chunks
retriever = vectordb.as_retriever(search_kwargs={"k": 3})

from langchain_core.messages import HumanMessage
from input_guard import check_input, log_blocked_input

# ── Secured query loop ─────────────────────────────────────────────────────────
print("\nSecured RAG Pipeline ready. Type 'quit' to exit.\n")

while True:
    query = input("Your question: ").strip()

    if query.lower() == "quit":
        print("Exiting.")
        break

    # Run input guard BEFORE touching the LLM
    guard_result = check_input(query)

    if not guard_result["allowed"]:
        print(f"\n🚫 BLOCKED: {guard_result['reason']}\n")
        log_blocked_input(query, guard_result)
        continue

    # Safe — retrieve + generate
    relevant_docs = retriever.invoke(query)
    context = "\n\n".join([doc.page_content for doc in relevant_docs])

    response = llm.invoke([HumanMessage(content=(
        f"Answer based only on this context:\n\n{context}\n\nQuestion: {query}"
    ))])

    print(f"\n✅ Answer: {response.content}")
    print(f"   Sources: {len(relevant_docs)} chunks\n")