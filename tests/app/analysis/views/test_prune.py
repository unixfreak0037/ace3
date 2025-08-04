from flask import url_for
import pytest

from saq.constants import DEFAULT_PRUNE, DEFAULT_PRUNE_VOLATILE


@pytest.mark.integration
def test_toggle_prune_get_request_no_session(web_client):
    """Test toggle_prune GET request when prune not in session."""
    result = web_client.get(url_for("analysis.toggle_prune"))
    
    assert result.status_code == 302  # redirect
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that session was initialized with default and then toggled
    with web_client.session_transaction() as sess:
        assert sess['prune'] == (not DEFAULT_PRUNE)


@pytest.mark.integration 
def test_toggle_prune_post_request_no_session(web_client):
    """Test toggle_prune POST request when prune not in session."""
    result = web_client.post(url_for("analysis.toggle_prune"))
    
    assert result.status_code == 302  # redirect
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that session was initialized with default and then toggled
    with web_client.session_transaction() as sess:
        assert sess['prune'] == (not DEFAULT_PRUNE)


@pytest.mark.integration
def test_toggle_prune_with_existing_session_true(web_client):
    """Test toggle_prune when session already has prune=True."""
    # Set initial session state
    with web_client.session_transaction() as sess:
        sess['prune'] = True
    
    result = web_client.get(url_for("analysis.toggle_prune"))
    
    assert result.status_code == 302
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that prune was toggled to False
    with web_client.session_transaction() as sess:
        assert sess['prune'] is False


@pytest.mark.integration
def test_toggle_prune_with_existing_session_false(web_client):
    """Test toggle_prune when session already has prune=False."""
    # Set initial session state
    with web_client.session_transaction() as sess:
        sess['prune'] = False
    
    result = web_client.get(url_for("analysis.toggle_prune"))
    
    assert result.status_code == 302
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that prune was toggled to True
    with web_client.session_transaction() as sess:
        assert sess['prune'] is True


@pytest.mark.integration
def test_toggle_prune_with_alert_uuid(web_client):
    """Test toggle_prune with alert_uuid parameter."""
    test_uuid = "12345-67890-abcdef"
    
    result = web_client.get(url_for("analysis.toggle_prune", alert_uuid=test_uuid))
    
    assert result.status_code == 302
    # Check that redirect includes the alert_uuid
    assert f"alert_uuid={test_uuid}" in result.location
    
    with web_client.session_transaction() as sess:
        assert sess['prune'] is (not DEFAULT_PRUNE)


@pytest.mark.integration
def test_toggle_prune_volatile_get_request_no_session(web_client):
    """Test toggle_prune_volatile GET request when prune_volatile not in session."""
    result = web_client.get(url_for("analysis.toggle_prune_volatile"))
    
    assert result.status_code == 302  # redirect
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that session was initialized with default and then toggled
    with web_client.session_transaction() as sess:
        assert sess['prune_volatile'] is (not DEFAULT_PRUNE_VOLATILE)


@pytest.mark.integration
def test_toggle_prune_volatile_post_request_no_session(web_client):
    """Test toggle_prune_volatile POST request when prune_volatile not in session."""
    result = web_client.post(url_for("analysis.toggle_prune_volatile"))
    
    assert result.status_code == 302  # redirect
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that session was initialized with default and then toggled
    with web_client.session_transaction() as sess:
        assert sess['prune_volatile'] is (not DEFAULT_PRUNE_VOLATILE)


@pytest.mark.integration
def test_toggle_prune_volatile_with_existing_session_true(web_client):
    """Test toggle_prune_volatile when session already has prune_volatile=True."""
    # Set initial session state
    with web_client.session_transaction() as sess:
        sess['prune_volatile'] = True
    
    result = web_client.get(url_for("analysis.toggle_prune_volatile"))
    
    assert result.status_code == 302
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that prune_volatile was toggled to False
    with web_client.session_transaction() as sess:
        assert sess['prune_volatile'] is False


@pytest.mark.integration
def test_toggle_prune_volatile_with_existing_session_false(web_client):
    """Test toggle_prune_volatile when session already has prune_volatile=False."""
    # Set initial session state
    with web_client.session_transaction() as sess:
        sess['prune_volatile'] = False
    
    result = web_client.get(url_for("analysis.toggle_prune_volatile"))
    
    assert result.status_code == 302
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that prune_volatile was toggled to True
    with web_client.session_transaction() as sess:
        assert sess['prune_volatile'] is True


@pytest.mark.integration
def test_toggle_prune_volatile_with_non_bool_session_value(web_client):
    """Test toggle_prune_volatile when session has non-boolean prune_volatile value."""
    # Set initial session state to non-boolean value
    with web_client.session_transaction() as sess:
        sess['prune_volatile'] = "some_string"
    
    result = web_client.get(url_for("analysis.toggle_prune_volatile"))
    
    assert result.status_code == 302
    assert result.location.endswith(url_for("analysis.index"))
    
    # Check that prune_volatile was reset to default and then toggled
    with web_client.session_transaction() as sess:
        assert sess['prune_volatile'] is (not DEFAULT_PRUNE_VOLATILE)


@pytest.mark.integration
def test_toggle_prune_volatile_with_alert_uuid(web_client):
    """Test toggle_prune_volatile with alert_uuid parameter."""
    test_uuid = "12345-67890-abcdef"
    
    result = web_client.get(url_for("analysis.toggle_prune_volatile", alert_uuid=test_uuid))
    
    assert result.status_code == 302
    # Check that redirect includes the alert_uuid
    assert f"alert_uuid={test_uuid}" in result.location
    
    with web_client.session_transaction() as sess:
        assert sess['prune_volatile'] is (not DEFAULT_PRUNE_VOLATILE)


@pytest.mark.integration
def test_toggle_prune_multiple_toggles(web_client):
    """Test multiple successive calls to toggle_prune."""
    # First toggle
    result1 = web_client.get(url_for("analysis.toggle_prune"))
    assert result1.status_code == 302
    
    with web_client.session_transaction() as sess:
        first_state = sess['prune']
    
    # Second toggle
    result2 = web_client.get(url_for("analysis.toggle_prune"))
    assert result2.status_code == 302
    
    with web_client.session_transaction() as sess:
        second_state = sess['prune']
    
    # States should be opposite
    assert first_state != second_state
    
    # Third toggle should return to first state
    result3 = web_client.get(url_for("analysis.toggle_prune"))
    assert result3.status_code == 302
    
    with web_client.session_transaction() as sess:
        third_state = sess['prune']
    
    assert first_state == third_state


@pytest.mark.integration
def test_toggle_prune_volatile_multiple_toggles(web_client):
    """Test multiple successive calls to toggle_prune_volatile."""
    # First toggle
    result1 = web_client.get(url_for("analysis.toggle_prune_volatile"))
    assert result1.status_code == 302
    
    with web_client.session_transaction() as sess:
        first_state = sess['prune_volatile']
    
    # Second toggle
    result2 = web_client.get(url_for("analysis.toggle_prune_volatile"))
    assert result2.status_code == 302
    
    with web_client.session_transaction() as sess:
        second_state = sess['prune_volatile']
    
    # States should be opposite
    assert first_state != second_state
    
    # Third toggle should return to first state
    result3 = web_client.get(url_for("analysis.toggle_prune_volatile"))
    assert result3.status_code == 302
    
    with web_client.session_transaction() as sess:
        third_state = sess['prune_volatile']
    
    assert first_state == third_state


@pytest.mark.integration
def test_both_prune_functions_independent(web_client):
    """Test that toggle_prune and toggle_prune_volatile work independently."""
    # Toggle prune
    web_client.get(url_for("analysis.toggle_prune"))
    
    with web_client.session_transaction() as sess:
        prune_state = sess['prune']
    
    # Toggle prune_volatile
    web_client.get(url_for("analysis.toggle_prune_volatile"))
    
    with web_client.session_transaction() as sess:
        prune_volatile_state = sess['prune_volatile']
        # Prune state should remain unchanged
        assert sess['prune'] == prune_state
    
    # Toggle prune again
    web_client.get(url_for("analysis.toggle_prune"))
    
    with web_client.session_transaction() as sess:
        # prune_volatile state should remain unchanged
        assert sess['prune_volatile'] == prune_volatile_state
        # prune state should be toggled
        assert sess['prune'] != prune_state