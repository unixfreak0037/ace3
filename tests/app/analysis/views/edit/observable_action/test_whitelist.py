import pytest
from unittest.mock import Mock, patch
from flask import url_for


@pytest.fixture
def mock_alert():
    """Create a mock alert for testing."""
    alert = Mock()
    alert.uuid = "test-alert-uuid"
    alert.description = "Test Alert"
    alert.root_analysis = Mock()
    alert.root_analysis.load = Mock()
    alert.root_analysis.get_observable = Mock()
    return alert


@pytest.fixture
def mock_observable():
    """Create a mock observable for testing."""
    observable = Mock()
    observable.type = "ipv4"
    # Create a mock value that can be encoded
    mock_value = Mock()
    mock_value.encode = Mock(return_value=b"192.168.1.1")
    observable.value = mock_value
    observable.sha256_hex = "abcd1234"
    observable.sha256_bytes = bytes.fromhex("abcd1234")
    return observable


@pytest.mark.integration
class TestObservableActionWhitelist:
    """Tests for observable_action_whitelist function."""

    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_whitelist_no_alert(self, mock_get_alert, web_client):
        """Test when no alert is found."""
        mock_get_alert.return_value = None
        
        response = web_client.post(url_for('analysis.observable_action_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: unable to find alert" in response.data

    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_whitelist_alert_load_error(self, mock_get_alert, web_client, mock_alert):
        """Test when alert fails to load."""
        mock_alert.root_analysis.load.side_effect = Exception("Load failed")
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: unable to load alert" in response.data
        assert b"Load failed" in response.data

    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_whitelist_observable_not_found(self, mock_get_alert, web_client, mock_alert):
        """Test when observable is not found in alert."""
        mock_alert.root_analysis.get_observable.return_value = None
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: unable to find observable in alert" in response.data

    @patch('app.analysis.views.edit.observable_action.whitelist.add_observable_tag_mapping')
    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_whitelist_success(self, mock_get_alert, mock_add_tag, web_client, mock_alert, mock_observable):
        """Test successfully adding whitelist tag to an observable."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        mock_add_tag.return_value = True
        
        response = web_client.post(url_for('analysis.observable_action_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"whitelisting added" in response.data
        mock_add_tag.assert_called_once_with(mock_observable, 'whitelisted')

    @patch('app.analysis.views.edit.observable_action.whitelist.add_observable_tag_mapping')
    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_whitelist_add_tag_fails(self, mock_get_alert, mock_add_tag, web_client, mock_alert, mock_observable):
        """Test when add_observable_tag_mapping returns False."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        mock_add_tag.return_value = False
        
        response = web_client.post(url_for('analysis.observable_action_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed" in response.data
        mock_add_tag.assert_called_once_with(mock_observable, 'whitelisted')

    @patch('app.analysis.views.edit.observable_action.whitelist.add_observable_tag_mapping')
    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_whitelist_add_tag_exception(self, mock_get_alert, mock_add_tag, web_client, mock_alert, mock_observable):
        """Test when add_observable_tag_mapping raises an exception."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        mock_add_tag.side_effect = Exception("Database error")
        
        response = web_client.post(url_for('analysis.observable_action_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: Database error" in response.data
        mock_add_tag.assert_called_once_with(mock_observable, 'whitelisted')


@pytest.mark.integration
class TestObservableActionUnWhitelist:
    """Tests for observable_action_un_whitelist function."""

    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_un_whitelist_no_alert(self, mock_get_alert, web_client):
        """Test when no alert is found."""
        mock_get_alert.return_value = None
        
        response = web_client.post(url_for('analysis.observable_action_un_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: unable to find alert" in response.data

    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_un_whitelist_alert_load_error(self, mock_get_alert, web_client, mock_alert):
        """Test when alert fails to load."""
        mock_alert.root_analysis.load.side_effect = Exception("Load failed")
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_un_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: unable to load alert" in response.data
        assert b"Load failed" in response.data

    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_un_whitelist_observable_not_found(self, mock_get_alert, web_client, mock_alert):
        """Test when observable is not found in alert."""
        mock_alert.root_analysis.get_observable.return_value = None
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_un_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: unable to find observable in alert" in response.data

    @patch('app.analysis.views.edit.observable_action.whitelist.remove_observable_tag_mapping')
    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_un_whitelist_success(self, mock_get_alert, mock_remove_tag, web_client, mock_alert, mock_observable):
        """Test successfully removing whitelist tag from an observable."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        mock_remove_tag.return_value = True
        
        response = web_client.post(url_for('analysis.observable_action_un_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"removed whitelisting" in response.data
        mock_remove_tag.assert_called_once_with(mock_observable, 'whitelisted')

    @patch('app.analysis.views.edit.observable_action.whitelist.remove_observable_tag_mapping')
    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_un_whitelist_remove_tag_fails(self, mock_get_alert, mock_remove_tag, web_client, mock_alert, mock_observable):
        """Test when remove_observable_tag_mapping returns False."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        mock_remove_tag.return_value = False
        
        response = web_client.post(url_for('analysis.observable_action_un_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed" in response.data
        mock_remove_tag.assert_called_once_with(mock_observable, 'whitelisted')

    @patch('app.analysis.views.edit.observable_action.whitelist.remove_observable_tag_mapping')
    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_un_whitelist_remove_tag_exception(self, mock_get_alert, mock_remove_tag, web_client, mock_alert, mock_observable):
        """Test when remove_observable_tag_mapping raises an exception."""
        mock_alert.root_analysis.get_observable.return_value = mock_observable
        mock_get_alert.return_value = mock_alert
        mock_remove_tag.side_effect = Exception("Database error")
        
        response = web_client.post(url_for('analysis.observable_action_un_whitelist'), data={
            'id': 'test-uuid'
        })
        
        assert response.status_code == 200
        assert b"operation failed: Database error" in response.data
        mock_remove_tag.assert_called_once_with(mock_observable, 'whitelisted')

    @patch('app.analysis.views.edit.observable_action.whitelist.get_current_alert')
    def test_un_whitelist_missing_id_parameter(self, mock_get_alert, web_client, mock_alert):
        """Test when the 'id' parameter is missing from the request."""
        mock_alert.root_analysis.get_observable.return_value = None
        mock_get_alert.return_value = mock_alert
        
        response = web_client.post(url_for('analysis.observable_action_un_whitelist'), data={})
        
        assert response.status_code == 200
        assert b"operation failed: unable to find observable in alert" in response.data