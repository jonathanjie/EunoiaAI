# **Customer Service Chatbot**

A customer service chatbot powered by OpenAI's GPT-4 and Pinecone, capable of providing users with information based on a specific knowledge base.

## **Features**

- Customizable chatbot with a dedicated knowledge base
- Redis-based session management for maintaining context across user conversations
- Integrated with Pinecone for efficient document search and retrieval
- Easy-to-use web interface with chat functionality

## **Installation**

1. Clone the repository:

```
git clone https://github.com/yourusername/customer-service-chatbot.git
cd customer-service-chatbot
```

2. Create and activate a virtual environment:

```
python3 -m venv venv
source venv/bin/activate
```

3. Install the required dependencies:

```
pip install -r requirements.txt
```

4. Set up the necessary API keys and environment variables:

```
export OPENAI_API_KEY="your_openai_api_key"
export PINECONE_API_KEY="your_pinecone_api_key"
export PROMPTLAYER_API_KEY="your_promptlayer_api_key"
```

5. Run the Flask application:

```
python app.py
```

## **Usage**

1. Open a web browser and navigate to **`http://localhost:5000`**.
2. Interact with the chatbot using the provided chat interface.

## **License**

This project is licensed under the MIT License. See the **[LICENSE](https://chat.openai.com/chat/LICENSE)** file for details.

## **Contributing**

Contributions are welcome! Please read the **[CONTRIBUTING.md](https://chat.openai.com/chat/CONTRIBUTING.md)** file for guidelines on how to contribute to the project.