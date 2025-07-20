#!/usr/bin/env python3
#
# creates the unit test schema files

import os
import os.path
import random
import re
import shutil
import string
import sys

def main(): 
    for src_sql, dest_sql in [
        ('01-ace.sql', '21-ace-unittest.sql'),
        ('02-email-archive.sql', '22-email-archive-unittest.sql'),
        ('03-brocess.sql', '23-brocess-unittest.sql'),
        ('05-amc.sql', '25-amc-unittest.sql'), ]:
        with open(os.path.join('sql', src_sql), 'r', encoding='utf8') as fp_in:
            with open(os.path.join('sql.dev', dest_sql), 'w') as fp_out:
                for line in fp_in:
                    if line.startswith('CREATE DATABASE IF NOT EXISTS `') \
                    or line.startswith('ALTER DATABASE `') \
                    or line.startswith('USE `'):
                        line = re.sub(r'`([^`]+)`', r'`\1-unittest`', line)

                    fp_out.write(line)

    # this sucks -- a few of the integration tests require yet another ace database
    # XXX fix me!
    for src_sql, dest_sql in [
        ('01-ace.sql', '211-ace-unittest-2.sql'), ]:
        with open(os.path.join('sql', src_sql), 'r', encoding='utf8') as fp_in:
            with open(os.path.join('sql.dev', dest_sql), 'w') as fp_out:
                for line in fp_in:
                    if line.startswith('CREATE DATABASE IF NOT EXISTS `') \
                    or line.startswith('ALTER DATABASE `') \
                    or line.startswith('USE `'):
                        line = re.sub(r'`([^`]+)`', r'`\1-unittest-2`', line)

                    fp_out.write(line)

if __name__ == '__main__':
    main()
