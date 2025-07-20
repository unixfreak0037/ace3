from subprocess import run, PIPE

class SMBClient:
    def __init__(self, domain, username, password):
        self.domain = domain
        self.user = f"{username}%{password}"

    def execute(self, path, cmd, input=None):
        # break path into parts
        parts = path[2:].split('/')
        server = parts[0]
        share = parts[1]

        # cd into the dir if one was provided
        if len(parts) > 2:
            directory = '/'.join(parts[2:])
            cmd = f'cd "{directory}"; {cmd}'

        # run the command
        cmd = ['smbclient', '-W', self.domain, '-U', self.user, f'//{server}/{share}', '-c', cmd]
        r = run(cmd, input=input, stdout=PIPE, stderr=PIPE)

        # raise errors
        if r.returncode != 0:
            output = r.stdout.decode('utf-8').strip()
            if 'NT_STATUS_NO_SUCH_FILE' in output:
                path = output[len('NT_STATUS_NO_SUCH_FILE listing \\'):].replace('\\', '/')
                raise FileNotFoundError(f'no such file or directory: //{server}/{share}/{path}')
            raise Exception(output)

    # writes content to smb path
    def write(self, path, content):
        # break the file apart from the rest of the path
        path, fname = path.rsplit('/', 1)

        # pipe content as stdin to smbclient process which uses /dev/fd/0 (stdin file) to copy the input to the remote file
        self.execute(path, f'put /dev/fd/0 "{fname}"', input=content.encode('utf-8'))

    def delete(self, path):
        path, fname = path.rsplit('/', 1)
        self.execute(path, f'del "{fname}"')
