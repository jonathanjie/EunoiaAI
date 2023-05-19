from datetime import timedelta
from langchain.prompts.prompt import PromptTemplate
from langchain.chains import ConversationChain
from langchain.memory import ConversationSummaryBufferMemory
from langchain.chat_models import PromptLayerChatOpenAI
from django.contrib.sessions.models import Session

expiry_time = timedelta(seconds=86400)  # 24 hours

def init_chat_and_memory(context_data, primer_prompt=None, company_name=None, agent_display_name=None):
    data_1, data_2, data_3 = context_data
    company_name = company_name or "MarinaChain"
    agent_display_name = agent_display_name or "Mari-Chan"
    primer_prompt = primer_prompt or "[Meta Instructions]\nYou are a multilingual customer service agent called {bot_name}, for the company {company_name}."
    
    formatted_primer_prompt = primer_prompt.format(company_name=company_name, bot_name=agent_display_name)

    instructions = """* Cut off after the AI's response is done. Don't generate a new question on behalf of Human.
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

    full_template = formatted_primer_prompt + "\n\n" + instructions

    formatted_template = full_template.format(
        data_1=data_1, data_2=data_2, data_3=data_3, history="{history}", input="{input}")

    PROMPT = PromptTemplate(
        input_variables=["history", "input"], template=formatted_template
    )

    # Initialize ChatGPT and Memoryindex
    chat = PromptLayerChatOpenAI(temperature=0, model_name="gpt-3.5-turbo", request_timeout=3600)
    memory = ConversationSummaryBufferMemory(llm=chat, max_token_limit=500)

    # Initialize the Conversation object
    conversation = ConversationChain(
        prompt=PROMPT, llm=chat, verbose=True, memory=memory)

    return conversation, memory

def save_convo_to_redis(request, memory, agent_namespace, session_id):
    session_key = f'bot_{agent_namespace}_{session_id}'
    session_data = request.session.get(session_key)
    convo_history = []

    if session_data:
        full_convo_history = session_data['full_convo_history']
    else:
        full_convo_history = []

    first_message_human = True if len(memory.buffer) == 0 else str(
        type(memory.buffer[0])) == "<class 'langchain.schema.HumanMessage'>"

    for message in memory.buffer:
        convo_history.append(message.content)

    full_convo_history += convo_history[-2:]

    summary = memory.moving_summary_buffer

    request.session[session_key] = {
        'summary': summary,
        'convo_history': convo_history,
        'full_convo_history': full_convo_history,
        'first_message_human': first_message_human
    }
    request.session.set_expiry(expiry_time)

    return full_convo_history

def restore_convo_from_redis(request, memory, agent_namespace, session_id):
    session_key = f'bot_{agent_namespace}_{session_id}'
    session_data = request.session.get(session_key)

    print("SESSION_ID:")
    print(session_id)
    print("SESSION_DATA:")
    print(session_data)

    if session_data:
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
    session_data = request.session.get(session_key)

    if session_data:
        full_convo_history = session_data['full_convo_history']
    else:
        full_convo_history = []

    return full_convo_history