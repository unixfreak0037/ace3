# vim: sw=4:ts=4:et

import os
import re

from subprocess import PIPE, Popen
from typing import List

whitespace_re = re.compile(r'\s')

def generate_wordlist(
        text_file: str=None, 
        text_content: str=None, 
        range_low: int=4, 
        range_high: int=14, 
        byte_limit: int=1024, 
        list_limit: int=1000,
        ) -> List[str]:
    """Given a text file or string, return a list of all the likely passwords, assuming the password is in there somewhere."""
    if not text_content:
        with open(text_file, 'rb') as fp:
            data = fp.read(byte_limit).decode(errors='ignore')
    else:
        data = text_content

    password_list = set()
    for r in range(range_low, range_high + 1):
        for i in range(0, byte_limit - r):
            password = data[i:i + r]
            if not password:
                continue

            # assume whitespace characters are not going to be in passwords
            if whitespace_re.search(password):
                continue

            password_list.add(password)
            if len(password_list) >= list_limit:
                break

    return list(password_list)

def crack_password(john_bin_path: str, hash_file: str, filename: str, mode: str) -> str:
    p = Popen([os.path.join(john_bin_path, 'john'), mode, hash_file], stdin=PIPE, stdout=PIPE,
              stderr=PIPE)
    _, _ = p.communicate()

    p = Popen([os.path.join(john_bin_path, 'john'), f'--show', hash_file], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()

    password = None
    for line in stdout.decode(errors='ignore').split('\n'):
        if os.path.basename(filename) in line:
            password = line.split(':')[1]

    return password