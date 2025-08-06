import os
from io import BytesIO

import pytest
from flask import url_for

from saq.database.model import Alert


@pytest.mark.integration
class TestUploadFile:
    """Test the upload_file function in misc.py."""
    
    def test_upload_file_no_file_specified(self, web_client):
        """Test upload_file when no file is specified."""
        data = {
            'comment': 'test comment',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), data=data)
        
        # Should redirect to analysis.file with flash message
        assert result.status_code == 302
        assert result.location == url_for('analysis.file')
    
    def test_upload_file_new_alert_success(self, web_client):
        """Test successful file upload creating new alert."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse

        # Create test file
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': ''
        }
            
        result = web_client.post(url_for('analysis.upload_file'), 
                                data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.index with new alert UUID
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert 'direct=' in result.location
        
        # Extract the alert UUID from the redirect URL
        parsed_url = urlparse(result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        # Verify the alert was actually created in the database
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
        assert alert.uuid == alert_uuid
        assert alert.alert_type == 'manual_upload'
        assert alert.description == 'Manual File upload test_file.txt'
        assert alert.tool == 'Manual File Upload - test_file.txt'
        
        # Verify the alert can be loaded and contains the uploaded file
        alert.load()  # load() returns None but populates _root_analysis
        root_analysis = alert.root_analysis
        assert root_analysis is not None
        
        # Check that the file observable was added
        file_observables = [obs for obs in root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 1
        assert file_observables[0].file_name == 'test_file.txt'
        
        # Verify the file was actually saved to disk
        file_observable = file_observables[0]
        assert os.path.exists(file_observable.full_path)
        with open(file_observable.full_path, 'rb') as f:
            assert f.read() == test_content
    
    def test_upload_file_existing_alert_success(self, web_client):
        """Test successful file upload to existing alert."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # First create an existing alert
        initial_data = {
            'file_path': (BytesIO(b'initial content'), 'initial_file.txt'),
            'comment': 'initial comment',
            'alert_uuid': ''
        }
        
        initial_result = web_client.post(url_for('analysis.upload_file'), 
                                       data=initial_data, content_type='multipart/form-data')
        
        # Extract the alert UUID from the redirect URL
        parsed_url = urlparse(initial_result.location)
        query_params = parse_qs(parsed_url.query)
        existing_alert_uuid = query_params['direct'][0]
        
        # Now upload to the existing alert
        test_content = b'test file content for existing alert'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': existing_alert_uuid
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.index
        assert result.status_code == 302
        assert '/analysis' in result.location
        
        # Verify the alert was updated with the new file
        alert = get_alert_by_uuid(existing_alert_uuid)
        assert alert is not None
        alert.load()
        root_analysis = alert.root_analysis
        
        # Should now have 2 file observables
        file_observables = [obs for obs in root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 2
        
        # Verify both files exist
        file_names = [obs.file_name for obs in file_observables]
        assert 'initial_file.txt' in file_names
        assert 'test_file.txt' in file_names
    
    def test_upload_file_nonexistent_alert(self, web_client):
        """Test upload_file with non-existent alert UUID."""
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': 'nonexistent-uuid-12345'
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.index when alert doesn't exist
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_upload_file_empty_filename(self, web_client):
        """Test upload_file with empty filename."""
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), ''),  # Empty filename
            'comment': 'test comment',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should redirect to analysis.file when filename is empty
        assert result.status_code == 302
        assert result.location == url_for('analysis.file')
    
    def test_upload_file_large_file(self, web_client):
        """Test upload_file with large file content."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # Create a larger test file (1MB)
        test_content = b'A' * (1024 * 1024)
        data = {
            'file_path': (BytesIO(test_content), 'large_test_file.txt'),
            'comment': 'large file test comment',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should successfully handle large file
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert 'direct=' in result.location
        
        # Extract the alert UUID and verify the file was saved
        parsed_url = urlparse(result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
        alert.load()
        
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 1
        assert file_observables[0].file_name == 'large_test_file.txt'
        
        # Verify the large file was actually saved correctly
        with open(file_observables[0].full_path, 'rb') as f:
            saved_content = f.read()
            assert len(saved_content) == len(test_content)
            assert saved_content == test_content
    
    def test_upload_file_special_characters_filename(self, web_client):
        """Test upload_file with special characters in filename."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        test_content = b'test file content with special chars'
        data = {
            'file_path': (BytesIO(test_content), 'test file with spaces & symbols!@#.txt'),
            'comment': 'special filename test',
            'alert_uuid': ''
        }
        
        result = web_client.post(url_for('analysis.upload_file'), 
                               data=data, content_type='multipart/form-data')
        
        # Should successfully handle special characters in filename
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert 'direct=' in result.location
        
        # Extract the alert UUID and verify the file was saved
        parsed_url = urlparse(result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
        alert.load()
        
        file_observables = [obs for obs in alert.root_analysis.observables if obs.type == 'file']
        assert len(file_observables) == 1
        assert file_observables[0].file_name == 'test file with spaces & symbols!@#.txt'
        
        # Verify the file was actually saved
        assert os.path.exists(file_observables[0].full_path)
        with open(file_observables[0].full_path, 'rb') as f:
            assert f.read() == test_content


@pytest.mark.integration  
class TestAnalyzeAlert:
    """Test the analyze_alert function in misc.py."""
    
    def test_analyze_alert_no_alert_uuid(self, web_client):
        """Test analyze_alert when no alert_uuid parameter is provided."""
        # Call analyze_alert without providing alert_uuid form parameter
        result = web_client.post(url_for('analysis.analyze_alert'))
        
        # Should redirect to analysis.index with flash message about missing UUID
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_analyze_alert_with_existing_alert(self, web_client):
        """Test analyze_alert with valid alert_uuid parameter."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # First create an alert
        test_content = b'test file content'
        data = {
            'file_path': (BytesIO(test_content), 'test_file.txt'),
            'comment': 'test comment',
            'alert_uuid': ''
        }
        
        upload_result = web_client.post(url_for('analysis.upload_file'), 
                                      data=data, content_type='multipart/form-data')
        
        # Extract the alert UUID
        parsed_url = urlparse(upload_result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        # Now analyze the alert by passing the alert_uuid as form parameter
        analyze_data = {'alert_uuid': alert_uuid}
        result = web_client.post(url_for('analysis.analyze_alert'), data=analyze_data)
        
        # Should redirect back to analysis.index with the same alert UUID
        assert result.status_code == 302
        assert '/analysis' in result.location
        assert f'direct={alert_uuid}' in result.location
        
        # Verify the alert still exists and was scheduled for processing
        alert = get_alert_by_uuid(alert_uuid)
        assert alert is not None
    
    def test_analyze_alert_nonexistent_uuid(self, web_client):
        """Test analyze_alert with nonexistent alert_uuid."""
        # Try to analyze an alert with a nonexistent UUID
        analyze_data = {'alert_uuid': 'nonexistent-uuid-12345'}
        result = web_client.post(url_for('analysis.analyze_alert'), data=analyze_data)
        
        # Should redirect to analysis.index with flash message about alert not found
        assert result.status_code == 302
        assert result.location == url_for('analysis.index')
    
    def test_analyze_alert_schedule_functionality(self, web_client):
        """Test that analyze_alert properly schedules the alert for reanalysis."""
        from saq.database.util.alert import get_alert_by_uuid
        from urllib.parse import parse_qs, urlparse
        
        # Create an alert first
        test_content = b'test file for scheduling'
        data = {
            'file_path': (BytesIO(test_content), 'schedule_test.txt'),
            'comment': 'test scheduling',
            'alert_uuid': ''
        }
        
        upload_result = web_client.post(url_for('analysis.upload_file'), 
                                      data=data, content_type='multipart/form-data')
        
        # Extract alert UUID
        parsed_url = urlparse(upload_result.location)
        query_params = parse_qs(parsed_url.query)
        alert_uuid = query_params['direct'][0]
        
        # Get the alert before scheduling
        alert_before = get_alert_by_uuid(alert_uuid)
        assert alert_before is not None
        
        # Call analyze_alert with alert_uuid form parameter
        analyze_data = {'alert_uuid': alert_uuid}
        result = web_client.post(url_for('analysis.analyze_alert'), data=analyze_data)
        
        # Should redirect successfully
        assert result.status_code == 302
        assert f'direct={alert_uuid}' in result.location
        
        # Verify the alert still exists after scheduling
        alert_after = get_alert_by_uuid(alert_uuid)
        assert alert_after is not None
        assert alert_after.uuid == alert_uuid


@pytest.mark.unit
class TestMiscHelperFunctions:
    """Test any helper functions or utilities in misc.py if they exist."""
    
    def test_imports_and_module_structure(self):
        """Test that the module imports correctly and has expected structure."""
        import app.analysis.views.misc as misc_module
        
        # Verify expected functions exist
        assert hasattr(misc_module, 'upload_file')
        assert hasattr(misc_module, 'analyze_alert')
        
        # Verify they are callable
        assert callable(misc_module.upload_file)
        assert callable(misc_module.analyze_alert)


@pytest.mark.integration
def test_misc_routes_require_login(app):
    """Test that misc routes require authentication."""
    # Create a client without auto-login
    with app.test_client() as client:
        # Test upload_file requires login
        result = client.post(url_for('analysis.upload_file'))
        assert result.status_code == 302  # Redirect to login
        
        # Test analyze_alert requires login  
        result = client.post(url_for('analysis.analyze_alert'))
        assert result.status_code == 302  # Redirect to login


@pytest.mark.integration
def test_misc_routes_only_accept_post(web_client):
    """Test that misc routes only accept POST methods."""
    # Test upload_file only accepts POST
    result = web_client.get(url_for('analysis.upload_file'))
    assert result.status_code == 405  # Method not allowed
    
    # Test analyze_alert only accepts POST
    result = web_client.get(url_for('analysis.analyze_alert'))  
    assert result.status_code == 405  # Method not allowed