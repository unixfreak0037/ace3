import functools
import json


def json_parse(fileobj, decoder=json.JSONDecoder(), buffersize=2048):
    """Utility iterator function that yields JSON objects from a file that contains multiple JSON objects.
       The iterator returns a tuple of (json_object, next_position) where next_position is the position in the
       file the next parsing would take place at."""
    buffer = ''
    reference_position = fileobj.tell() # remember where we're starting
    for chunk in iter(functools.partial(fileobj.read, buffersize), ''):
        buffer += chunk
        processed_buffer_size = 0
        while buffer:
            try:
                # index is where we stopped parsing at (where we'll start next time)
                result, index = decoder.raw_decode(buffer)

                buffer_size = len(buffer)
                buffer = buffer[index:].lstrip()
                processed_buffer_size = buffer_size - len(buffer)
                reference_position += processed_buffer_size

                yield result, reference_position

            except ValueError:
                # Not enough data to decode, read more
                break