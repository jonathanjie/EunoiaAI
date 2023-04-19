from langchain.prompts.prompt import PromptTemplate
import os
from datetime import timedelta
import pinecone
from langchain.chains import ConversationChain
from langchain.memory import ConversationSummaryBufferMemory
from langchain.chat_models import PromptLayerChatOpenAI
from django.conf import settings

expiry_time = timedelta(seconds=86400)  # 24 hours

def init_chat_and_memory(context_data):
    data_1, data_2, data_3 = context_data
    template = """[Meta Instructions]\nYou are a multilingual customer service agent called {bot_name}, for the company MarinaChain. You are to help the user with their queries. You are to solely provide the user with concise information, based on data from your knowledge bank.

* Cut off after the AI's response is done. Don't generate a new question on behalf of Human.
* If you don't know the answer, just say that you don't know, don't try to make up an answer.
* If the user is either unsatisfied or frustrated, or needs action beyond just getting a question answered, ask them if they need to speak to a human agent. If they confirm, let them know kindly that you'll be escalating, and also print a [ESCALATE] to signal the system to pass the case to a human.
* Don't entertain any random requests/questions the user asks you, as your sole focus is a customer service AI.
* If the answer is a very long instruction, break it up into steps for easier readability.

Use this data (pulled from the knowledge bank) to answer the user's question, if relevant:

| Source Number | Info |
|------|-------|
| 1 | {data_1} |
| 2 | {data_2} |
| 3 | {data_3} |

Current conversation:
{history}
Human: {input}
AI:"""

    formatted_template = template.format(
        bot_name="Mari-Chan", data_1=data_1, data_2=data_2, data_3=data_3, history="{history}", input="{input}")

    PROMPT = PromptTemplate(
        input_variables=["history", "input"], template=formatted_template
    )

    # Initialize ChatGPT and Memoryindex
    chat = PromptLayerChatOpenAI(temperature=0)
    memory = ConversationSummaryBufferMemory(llm=chat, max_token_limit=100)

    # Initialize the Conversation object
    conversation = ConversationChain(
        prompt=PROMPT, llm=chat, verbose=True, memory=memory)

    return conversation, memory