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

print("\n--- Querying RAG ---")
query = "What is prompt injection and how does indirect injection work?"

# Retrieve relevant chunks
retriever = vectordb.as_retriever(search_kwargs={"k": 3})
relevant_docs = retriever.invoke(query)

# Build context from retrieved chunks
context = "\n\n".join([doc.page_content for doc in relevant_docs])

# Ask Claude with context injected
from langchain_core.messages import HumanMessage
response = llm.invoke([
    HumanMessage(content=f"Answer based only on this context:\n\n{context}\n\nQuestion: {query}")
])

print(f"\nAnswer: {response.content}")
print(f"\nSources used: {len(relevant_docs)} chunks")