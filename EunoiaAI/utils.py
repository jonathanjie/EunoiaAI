from datetime import timedelta
import pinecone
from langchain.vectorstores import Pinecone
from langchain.embeddings.openai import OpenAIEmbeddings

from langchain.prompts.prompt import PromptTemplate
from langchain.chains import ConversationChain
from langchain.memory import ConversationSummaryBufferMemory
from langchain.chat_models import PromptLayerChatOpenAI
from django.contrib.sessions.models import Session
from django.shortcuts import get_object_or_404
from django.conf import settings
from .models import Agent, UserProfile, APIKey, Organization
import redis
import json

expiry_time = timedelta(seconds=86400)  # 24 hours

redis_instance = redis.StrictRedis.from_url(settings.REDIS_URL)

# Initialize Pinecone embedding function
embedding = OpenAIEmbeddings(openai_api_key=settings.OPENAI_API_KEY)

def process_message(request, api_key, user_input, session_id, agent_namespace):
    """
    Process a message and return a response using the specified agent namespace.

    :param api_key: API key.
    :param user_input: User input message.
    :param session_id: Session ID.
    :param agent_namespace: The namespace for the agent used in the conversation.
    :return: Dictionary with the response message or error message with the corresponding status code.
    """
    try:
        organization = APIKey.objects.get(key=api_key).organization
    except APIKey.DoesNotExist:
        return {"error": "Invalid API key or secret.", "status": 403}

    agent = get_object_or_404(Agent, namespace=agent_namespace)
    
    # Restore conversation from Redis
    conversation_history = get_convo_history_from_redis(
        request, agent_namespace, session_id)
    
    # query_text = '\n\n'.join(conversation_history[-1:]) + "\n\n" + user_input
    query_text = user_input
    print(f'QUERY TEXT:\n{query_text}')

    # Initialize Pinecone with the given namespace
    docsearch = Pinecone.from_existing_index(
        embedding=embedding, index_name=settings.PINECONE_INDEX)

    # Retrieve relevant data from vector store
    data_1, data_2, data_3 = "", "", ""
    query_reply = docsearch.similarity_search(
            query_text, namespace=agent_namespace)
    
    if len(query_reply) > 0:
        data_1 = query_reply[0].page_content
    if len(query_reply) > 1:
        data_2 = query_reply[1].page_content
    if len(query_reply) > 2:
        data_3 = query_reply[2].page_content

    # query_reply = docsearch.similarity_search(
    #     query_text, namespace=agent_namespace)
    # data_1, data_2, data_3 = [
    #     q.page_content for q in query_reply[:3]] + [""] * (3 - len(query_reply))
    # data_2 = data_2 or data_1
    # data_3 = data_3 or data_2

    # Initialize conversation and memory for the specific session
    conversation, memory = init_chat_and_memory(
        (data_1, data_2, data_3), agent.primer_prompt, agent.company_name, agent.agent_display_name)

    # Restore conversation from Redis into memory
    restore_convo_from_redis(
        request, memory, agent_namespace, session_id)

    response = conversation.predict(input=user_input)

    # Save the conversation to Redis
    full_convo_history = save_convo_to_redis(
        request, memory, agent_namespace, session_id)
        
    print("CONVO HISTORY:")
    print(full_convo_history)

    return {"response": response, "full_convo_history": full_convo_history}

def init_chat_and_memory(context_data, primer_prompt=None, company_name=None, agent_display_name=None):
    data_1, data_2, data_3 = context_data
    company_name = company_name or "MarinaChain"
    agent_display_name = agent_display_name or "Mari-Chan"
    primer_prompt = primer_prompt or "[Meta Instructions]\nYou are a multilingual customer service agent called {bot_name}, for the company {company_name}."
    
    formatted_primer_prompt = primer_prompt.format(company_name=company_name, bot_name=agent_display_name)

    instructions = """* Cut off after the AI's response is done. Don't generate a new question on behalf of Human.
* If you don't know the answer, just say that you don't know, don't try to make up an answer.
* If the question is about a certain fact, and it's not available in the given knowledge base, say you don't know or are unsure. IMPORTANT: Use only the information given to you below, and not on general knowledge.
* If the user asks for any company details, only use the details given from the knowledge bank.
* If the user is either unsatisfied or frustrated, or needs action beyond just getting a question answered, ask them if they need to speak to a human agent. If they say yes, print a [ESCALATE] in the same reply to signal the system to pass the case to a human.
* Don't entertain any random requests/questions the user asks you, as your sole focus is a customer service AI.
* If the answer is a very long instruction, break it up into steps for easier readability.
* Only respond with links if it is available in the given knowledge bank.

ONLY use this data (pulled from the knowledge bank) to answer the user's question, if relevant, and nothing else:

| Source Number | Knowledge Bank Info |
|------|-------|
| 1 | {data_1} |
| 2 | {data_2} |
| 3 | {data_3} |

---

### Current conversation:
{history}
Human: {input}
AI:"""

    full_template = formatted_primer_prompt + "\n\n" + instructions

    formatted_template = full_template.format(
        data_1=data_1, data_2=data_2, data_3=data_3, history="{history}", input="{input}")

    PROMPT = PromptTemplate(
        input_variables=["history", "input"], template=formatted_template
    )

    # Initialize ChatGPT and Memoryindex
    chat = PromptLayerChatOpenAI(temperature=0, model_name="gpt-3.5-turbo-16k", request_timeout=3600)
    memory = ConversationSummaryBufferMemory(llm=chat, max_token_limit=500)

    # Initialize the Conversation object
    conversation = ConversationChain(
        prompt=PROMPT, llm=chat, verbose=True, memory=memory)

    return conversation, memory
    
def save_convo_to_redis(request, memory, agent_namespace, session_id):
    session_key = f'bot_{agent_namespace}_{session_id}'
    convo_history = []

    session_data = redis_instance.get(session_key)

    if session_data:
        session_data = json.loads(session_data)
        full_convo_history = session_data['full_convo_history']
    else:
        full_convo_history = []

    first_message_human = True if len(memory.buffer) == 0 else str(
        type(memory.buffer[0])) == "<class 'langchain.schema.HumanMessage'>"

    for message in memory.buffer:
        convo_history.append(message.content)

    full_convo_history += convo_history[-2:]

    summary = memory.moving_summary_buffer

    session_data = {
        'summary': summary,
        'convo_history': convo_history,
        'full_convo_history': full_convo_history,
        'first_message_human': first_message_human
    }

    redis_instance.set(session_key, json.dumps(session_data))
    redis_instance.expire(session_key, expiry_time)  # set the expiry time

    return full_convo_history

def restore_convo_from_redis(request, memory, agent_namespace, session_id):
    session_key = f'bot_{agent_namespace}_{session_id}'
    session_data = redis_instance.get(session_key)

    print("SESSION_ID:")
    print(session_id)
    print("SESSION_DATA:")
    print(session_data)

    if session_data:
        session_data = json.loads(session_data)
        summary = session_data['summary']
        convo_history = session_data['convo_history']
        first_message_human = session_data['first_message_human']

        memory.moving_summary_buffer = summary

        if not first_message_human:
            convo_history.insert(0, '')

        for i in range(0, len(convo_history) - 1, 2):
            memory.save_context({"input": convo_history[i]},
                                {"output": convo_history[i + 1]})

def get_convo_history_from_redis(request, agent_namespace, session_id):
    session_key = f'bot_{agent_namespace}_{session_id}'
    session_data = redis_instance.get(session_key)

    if session_data:
        session_data = json.loads(session_data)
        full_convo_history = session_data['full_convo_history']
    else:
        full_convo_history = []

    return full_convo_history