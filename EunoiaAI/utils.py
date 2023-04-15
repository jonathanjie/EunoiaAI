from django.contrib.sessions.models import Session
from .config import expiry_time

### Function to save convo into Redis ###
def save_convo_to_redis(request, memory, session_id):
    """
    Save the current conversation to Redis.

    Args:
        session_id (str): The session identifier.

    Returns:
        None
    """
    convo_history = []

    # Check whether the first message in the current `memory.buffer` is by the human or AI  
    first_message_human = True if len(memory.buffer) == 0 else str(
        type(memory.buffer[0])) == "<class 'langchain.schema.HumanMessage'>"

    for message in memory.buffer:
        # feed message.content into a list called convo_history
        convo_history.append(message.content)

    summary = memory.moving_summary_buffer

    # Save summary, convo_history and first_message_human into Redis with 'bot_{session_id}' as key
    session_key = 'bot_{}'.format(session_id)
    request.session[session_key] = {
        'summary': summary,
        'convo_history': convo_history,
        'first_message_human': first_message_human
    }
    request.session.set_expiry(expiry_time)


### Function to restore convo from Redis ###
def restore_convo_from_redis(request, memory, session_id):
    """
    Restore the conversation from Redis.

    Args:
        session_id (str): The session identifier.

    Returns:
        None
    """
    # Uses 'bot_{session_id}' as key to check if session exists
    session_data_tuple = session.get('bot_{}'.format(session_id))

    # if not session_data_tuple:
    # If session doesn't exist:
    # memory.moving_summary_buffer = "[Meta Instructions]\nYou are a customer service agent called Mari-Chan, and your goal is to help the user with their queries. Your goal is to solely provide the user with information, based on data from your knowledge bank."

    if session_data_tuple:
        # If session exists:
        # Extract the dictionary from the tuple
        session_data = session_data_tuple[0]
        print("SESSION DATA:")
        print(session_data)
        summary = session_data['summary']
        convo_history = session_data['convo_history']
        first_message_human = session_data['first_message_human']

        # Restore the summary
        memory.moving_summary_buffer = summary

        # Restore the conversation history
        if not first_message_human:
            convo_history.insert(0, '')

        for i in range(0, len(convo_history) - 1, 2):
            memory.save_context({"input": convo_history[i]},
                                {"output": convo_history[i + 1]})
