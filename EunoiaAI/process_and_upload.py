import os
import shutil
import zipfile
from langchain.document_loaders import (
    NotionDirectoryLoader,
    PyPDFLoader,
    SeleniumURLLoader,
    BSHTMLLoader,
    CSVLoader,
)
from langchain.text_splitter import CharacterTextSplitter, TokenTextSplitter
from langchain.vectorstores import Pinecone
from langchain.embeddings.openai import OpenAIEmbeddings
from typing import List
from langchain.docstore.document import Document
import json
import pinecone
import requests
import tempfile
from django.conf import settings


def process_and_upload(
    input_data, file_type, pinecone_api_key, pinecone_api_env, pinecone_index_name
):
    # Choose the appropriate loader based on the file type
    if file_type == "notion":
        # Unzip the Notion export
        notion_directory = os.path.join(
            os.path.dirname(input_data), "Notion_DB")
        with zipfile.ZipFile(input_data, "r") as zip_ref:
            zip_ref.extractall(notion_directory)
        input_data = notion_directory
        loader = NotionDirectoryLoader(input_data)
    elif file_type == "csv":
        loader = CSVLoader(input_data)
    elif file_type == "javascript_website":
        print("SCRAPING WEBSITE WITH SELENIUM")
        urls = [url.strip() for url in input_data.split(',')]
        loader = SeleniumURLLoader(urls=urls)
    elif file_type == "html_website":
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(input_data, headers=headers)
        if response.status_code == 200:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as temp:
                temp.write(response.content)
                temp_path = temp.name
            loader = BSHTMLLoader(temp_path)
        else:
            print(f"Failed to fetch HTML content from {input_data}")
    elif file_type == "pdf":
        loader = PyPDFLoader(input_data)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")

    documents = loader.load()
    print("DOCUMENTS:")
    print(documents)

    # Split docs into smaller chunks
    text_splitter = TokenTextSplitter(chunk_size=500, chunk_overlap=0)
    docs = text_splitter.split_documents(documents)

    # Initialize Pinecone client and index
    pinecone.init(api_key=pinecone_api_key, environment=pinecone_api_env)
    index = pinecone.Index(index_name=pinecone_index_name)

    # Select OpenAI's Embeddings API as the embedding function
    embedding = OpenAIEmbeddings(openai_api_key=settings.OPENAI_API_KEY)

    # Insert the chunked documents into the Pinecone DB.
    # This uses Langchain's library to embed and insert
    docsearch = Pinecone.from_documents(
        docs, embedding=embedding, index_name=pinecone_index_name
    )