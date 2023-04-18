from django.contrib.sessions.models import Session
from .config import expiry_time

def save_convo_to_redis(request, memory, agent_namespace):
    session_key = f'bot_{agent_namespace}'
    convo_history = []

    first_message_human = True if len(memory.buffer) == 0 else str(
        type(memory.buffer[0])) == "<class 'langchain.schema.HumanMessage'>"

    for message in memory.buffer:
        convo_history.append(message.content)

    summary = memory.moving_summary_buffer

    request.session[session_key] = {
        'summary': summary,
        'convo_history': convo_history,
        'first_message_human': first_message_human
    }
    request.session.set_expiry(expiry_time)

def restore_convo_from_redis(request, memory, agent_namespace):
    session_key = f'bot_{agent_namespace}'
    session_data = request.session.get(session_key)

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
