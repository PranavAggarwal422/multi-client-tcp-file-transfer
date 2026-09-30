MESSAGE_DELIMITER = "\n"
FIELD_SEPARATOR = "|"


def make_message(command, *fields):
    """
    Create a protocol message.

    Format:
        COMMAND|FIELD1|FIELD2|...\n
    """
    message = FIELD_SEPARATOR.join((command,) + fields)
    return message + MESSAGE_DELIMITER

def parse_message(message):
    """
    Parse one complete protocol message.

    Returns:
        command, fields

    Example:
        "MSG|Bob|Hello Bob"
        -> ("MSG", ["Bob", "Hello Bob"])
    """

    parts = message.split(FIELD_SEPARATOR)
    command = parts[0]
    fields = parts[1:]

    return command, fields

