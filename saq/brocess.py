# vim: sw=4:ts=4:et:cc=120
#
# utility functions to use the brocess databases

from saq.database import execute_with_retry, get_db_connection
from saq.util import iterate_fqdn_parts

def query_brocess_by_fqdn(fqdn):
    with get_db_connection(name='brocess') as db:
        c = db.cursor()
        c.execute('SELECT SUM(numconnections) FROM httplog WHERE host = %s', (fqdn,))
    
        for row in c:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_dest_ipv4(ipv4):
    with get_db_connection(name='brocess') as db:
        c = db.cursor()
        c.execute('SELECT SUM(numconnections) FROM connlog WHERE destip = INET_ATON(%s)', (ipv4,))
    
        for row in c:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_email_conversation(source_email_address, dest_email_address):
    with get_db_connection(name='brocess') as db:
        c = db.cursor()
        c.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s AND destination = %s', (
                   source_email_address, dest_email_address,))
    
        for row in c:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def query_brocess_by_source_email(source_email_address):
    with get_db_connection(name='brocess') as db:
        c = db.cursor()
        c.execute('SELECT SUM(numconnections) FROM smtplog WHERE source = %s', (source_email_address,))
    
        for row in c:
            count = row[0]
            return int(count) if count is not None else 0

        raise RuntimeError("failed to return a row for sum() query operation !?")

def add_httplog(fqdn):
    with get_db_connection(name='brocess') as db:
        c = db.cursor()
        for fqdn_part in iterate_fqdn_parts(fqdn):
            execute_with_retry(db, c, """
INSERT INTO httplog ( host, numconnections, firstconnectdate ) 
VALUES ( LOWER(%s), 1, UNIX_TIMESTAMP(NOW()) )
ON DUPLICATE KEY UPDATE numconnections = numconnections + 1""", ( fqdn_part, ))

        db.commit()
