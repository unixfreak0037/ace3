import pytest
from subprocess import PIPE

import saq.smb
from saq.smb import SMBClient

@pytest.fixture
def mock_smb(monkeypatch):
    class Empty:
        pass
    result = Empty()
    run_args = Empty()
    def run(cmd, input=None, stderr=None, stdout=None):
        run_args.cmd = cmd
        run_args.input = input
        assert stderr == PIPE
        assert stdout == PIPE
        return result
    smb = SMBClient('company', 'me', '123')
    monkeypatch.setattr('saq.smb.run', run)
    def mock(code, output):
        result.returncode = code
        result.stdout = output.encode('utf-8')
        return smb, run_args
    return mock

@pytest.mark.unit
def test_smb_client_write(mock_smb):
    smb, run_args = mock_smb(0, 'success')
    smb.write('//server.com/shared/some/path/test.txt', 'hello world')

    assert run_args.input == 'hello world'.encode('utf-8')
    assert run_args.cmd == [
        'smbclient', 
        '-W', 'company',
        '-U', 'me%123',
        '//server.com/shared', 
        '-c', 'cd "some/path"; put /dev/fd/0 "test.txt"'
    ]

@pytest.mark.unit
def test_smb_client_delete(mock_smb):
    smb, run_args = mock_smb(0, 'success')
    smb.delete('//server.com/shared/some/path/test.txt')

    assert run_args.input == None
    assert run_args.cmd == [
        'smbclient', 
        '-W', 'company',
        '-U', 'me%123',
        '//server.com/shared', 
        '-c', 'cd "some/path"; del "test.txt"'
    ]

@pytest.mark.unit
def test_smb_client_file_not_found(mock_smb):
    smb, run_args = mock_smb(1, 'NT_STATUS_NO_SUCH_FILE listing \\some\\path\\test.txt\n')
    with pytest.raises(FileNotFoundError) as e:
        smb.delete('//server.com/shared/some/path/test.txt')

    assert str(e.value) == 'no such file or directory: //server.com/shared/some/path/test.txt'

@pytest.mark.unit
def test_smb_client_error(mock_smb):
    smb, run_args = mock_smb(1, 'what happened?')
    with pytest.raises(Exception) as e:
        smb.delete('//server.com/shared/some/path/test.txt')

    assert str(e.value) == 'what happened?'
