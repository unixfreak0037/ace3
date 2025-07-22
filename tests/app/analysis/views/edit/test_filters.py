import json
import pytest
from flask import url_for



@pytest.mark.integration
def test_set_sort_filter_new_field(web_client):
    """Test setting a new sort filter field."""
    with web_client.session_transaction() as sess:
        sess.clear()
    
    response = web_client.post(url_for("analysis.set_sort_filter"), data={
        "name": "alert_type"
    })
    
    assert response.status_code == 204
    assert response.data == b''
    
    with web_client.session_transaction() as sess:
        assert sess['sort_filter'] == 'alert_type'
        assert sess['sort_filter_desc'] == False
        assert sess['page_offset'] == 0
        assert 'checked' in sess and sess['checked'] == []


@pytest.mark.integration
def test_set_sort_filter_same_field_flips_direction(web_client):
    """Test setting the same sort filter field flips direction."""
    with web_client.session_transaction() as sess:
        sess['sort_filter'] = 'alert_type'
        sess['sort_filter_desc'] = False
    
    response = web_client.post(url_for("analysis.set_sort_filter"), data={
        "name": "alert_type"
    })
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert sess['sort_filter'] == 'alert_type'
        assert sess['sort_filter_desc'] == True


@pytest.mark.integration
def test_set_sort_filter_get_method(web_client):
    """Test setting sort filter via GET method."""
    response = web_client.get(url_for("analysis.set_sort_filter", name="description"))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert sess['sort_filter'] == 'description'
        assert sess['sort_filter_desc'] == False


@pytest.mark.integration
def test_reset_filters(web_client, analyst):
    """Test resetting filters to default state."""
    with web_client.session_transaction() as sess:
        sess['filters'] = [{"name": "custom", "values": ["test"]}]
        sess['sort_filter'] = 'custom'
        sess['sort_filter_desc'] = True
        sess['page_offset'] = 10
        sess['checked'] = ['uuid1', 'uuid2']
    
    response = web_client.get(url_for("analysis.reset_filters"))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert sess['page_offset'] == 0
        assert sess['sort_filter'] == 'Alert Date'
        assert sess['sort_filter_desc'] == True
        assert sess['checked'] == []
        # Check default filters are set
        assert len(sess['filters']) == 3
        filter_names = [f['name'] for f in sess['filters']]
        assert 'Disposition' in filter_names
        assert 'Owner' in filter_names
        assert 'Queue' in filter_names


@pytest.mark.integration
def test_reset_filters_special(web_client, analyst):
    """Test resetting filters with special time range."""
    with web_client.session_transaction() as sess:
        sess['filters'] = [{"name": "custom", "values": ["test"]}]
        sess['page_offset'] = 10
        sess['checked'] = ['uuid1']
    
    response = web_client.get(url_for("analysis.reset_filters_special", hours="24"))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert sess['page_offset'] == 0
        assert sess['sort_filter'] == 'Alert Date'
        assert sess['sort_filter_desc'] == True
        assert sess['checked'] == []
        # Check special filters are set
        assert len(sess['filters']) == 2
        filter_names = [f['name'] for f in sess['filters']]
        assert 'Queue' in filter_names
        assert 'Alert Date' in filter_names


@pytest.mark.integration
def test_set_filters_post_method(web_client):
    """Test setting filters via POST method."""
    filters_data = [
        {"name": "Disposition", "inverted": False, "values": ["OPEN", "CLOSED"]},
        {"name": "Queue", "inverted": True, "values": ["default"]}
    ]
    
    response = web_client.post(url_for("analysis.set_filters"), data={
        "filters": json.dumps(filters_data)
    })
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert sess['filters'] == filters_data
        assert sess['page_offset'] == 0
        assert sess['checked'] == []


@pytest.mark.integration
def test_set_filters_get_method_with_redirect(web_client):
    """Test setting filters via GET method with redirect."""
    filters_data = [{"name": "Description", "inverted": False, "values": ["test"]}]
    
    response = web_client.get(url_for("analysis.set_filters", 
                                      filters=json.dumps(filters_data),
                                      redirect="true"))
    
    assert response.status_code == 302
    assert "manage" in response.location
    
    with web_client.session_transaction() as sess:
        assert sess['filters'] == filters_data


@pytest.mark.integration
def test_set_filters_get_method_no_redirect(web_client):
    """Test setting filters via GET method without redirect."""
    filters_data = [{"name": "Description", "inverted": False, "values": ["test"]}]
    
    response = web_client.get(url_for("analysis.set_filters", 
                                      filters=json.dumps(filters_data)))
    
    assert response.status_code == 204


@pytest.mark.integration
def test_add_filter_new_filter(web_client):
    """Test adding a new filter."""
    with web_client.session_transaction() as sess:
        sess.clear()
    
    filter_data = {
        "name": "Description",
        "inverted": False,
        "values": ["test value"]
    }
    
    response = web_client.post(url_for("analysis.add_filter"), data={
        "filter": json.dumps(filter_data)
    })
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert len(sess['filters']) == 1
        assert sess['filters'][0] == filter_data
        assert sess['page_offset'] == 0
        assert sess['checked'] == []


@pytest.mark.integration
def test_add_filter_extend_existing(web_client):
    """Test adding values to an existing filter extends the filter's values."""
    existing_filter = {
        "name": "Description",
        "inverted": False,
        "values": ["existing value"]
    }
    
    with web_client.session_transaction() as sess:
        sess['filters'] = [existing_filter]
    
    filter_data = {
        "name": "Description", 
        "inverted": False,
        "values": ["new value"]
    }
    
    response = web_client.post(url_for("analysis.add_filter"), data={
        "filter": json.dumps(filter_data)
    })
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        # Should still have only one filter since we extended the existing one
        assert len(sess['filters']) == 1
        desc_filter = sess['filters'][0]
        assert desc_filter['name'] == 'Description'
        assert desc_filter['inverted'] == False
        # Both values should be in the same filter
        assert "existing value" in desc_filter['values']
        assert "new value" in desc_filter['values']
        assert len(desc_filter['values']) == 2


@pytest.mark.integration
def test_add_filter_different_inverted_creates_new(web_client):
    """Test adding filter with different inverted flag creates separate filter."""
    existing_filter = {
        "name": "Description",
        "inverted": False,
        "values": ["existing value"]
    }
    
    with web_client.session_transaction() as sess:
        sess['filters'] = [existing_filter]
    
    filter_data = {
        "name": "Description",
        "inverted": True,  # Different inverted flag
        "values": ["new value"]
    }
    
    response = web_client.post(url_for("analysis.add_filter"), data={
        "filter": json.dumps(filter_data)
    })
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        # Should have two filters now since inverted flags differ
        assert len(sess['filters']) == 2
        
        # Find filters by inverted flag
        non_inverted = next(f for f in sess['filters'] if not f['inverted'])
        inverted = next(f for f in sess['filters'] if f['inverted'])
        
        assert non_inverted['values'] == ["existing value"]
        assert inverted['values'] == ["new value"]


@pytest.mark.integration
def test_add_filter_get_method(web_client):
    """Test adding filter via GET method."""
    filter_data = {
        "name": "Queue",
        "inverted": True,
        "values": ["test_queue"]
    }
    
    response = web_client.get(url_for("analysis.add_filter", 
                                      filter=json.dumps(filter_data)))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert len(sess['filters']) == 1
        assert sess['filters'][0] == filter_data


@pytest.mark.integration
def test_remove_filter(web_client):
    """Test removing a specific filter value."""
    filters = [
        {
            "name": "Description",
            "inverted": False,
            "values": ["value1", "value2", "value3"]
        },
        {
            "name": "Queue",
            "inverted": False,
            "values": ["queue1"]
        }
    ]
    
    with web_client.session_transaction() as sess:
        sess['filters'] = filters
    
    response = web_client.get(url_for("analysis.remove_filter", 
                                      name="Description", 
                                      index="1"))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        desc_filter = next(f for f in sess['filters'] if f['name'] == 'Description')
        assert len(desc_filter['values']) == 2
        assert "value2" not in desc_filter['values']
        assert "value1" in desc_filter['values']
        assert "value3" in desc_filter['values']
        # Queue filter should remain unchanged
        assert len(sess['filters']) == 2


@pytest.mark.integration
def test_remove_filter_removes_empty_filter(web_client):
    """Test removing last value removes the entire filter."""
    filters = [
        {
            "name": "Description",
            "inverted": False,
            "values": ["only_value"]
        },
        {
            "name": "Queue",
            "inverted": False,
            "values": ["queue1"]
        }
    ]
    
    with web_client.session_transaction() as sess:
        sess['filters'] = filters
    
    response = web_client.get(url_for("analysis.remove_filter", 
                                      name="Description", 
                                      index="0"))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert len(sess['filters']) == 1
        assert sess['filters'][0]['name'] == 'Queue'


@pytest.mark.integration
def test_remove_filter_category(web_client):
    """Test removing an entire filter category."""
    filters = [
        {
            "name": "Description",
            "inverted": False,
            "values": ["value1", "value2"]
        },
        {
            "name": "Queue",
            "inverted": False,
            "values": ["queue1"]
        },
        {
            "name": "Owner",
            "inverted": True,
            "values": ["user1"]
        }
    ]
    
    with web_client.session_transaction() as sess:
        sess['filters'] = filters
    
    response = web_client.get(url_for("analysis.remove_filter_category", 
                                      name="Queue"))
    
    assert response.status_code == 204
    
    with web_client.session_transaction() as sess:
        assert len(sess['filters']) == 2
        filter_names = [f['name'] for f in sess['filters']]
        assert 'Queue' not in filter_names
        assert 'Description' in filter_names
        assert 'Owner' in filter_names


@pytest.mark.integration
def test_new_filter_option(web_client):
    """Test rendering new filter option template."""
    response = web_client.get(url_for("analysis.new_filter_option"))
    
    assert response.status_code == 200
    assert b'alert_filter_input.html' in response.data or b'Description' in response.data


@pytest.mark.integration
def test_new_filter_option_post(web_client):
    """Test new filter option via POST method."""
    response = web_client.post(url_for("analysis.new_filter_option"))
    
    assert response.status_code == 200


@pytest.mark.integration
def test_set_sort_filter_missing_name_parameter(web_client):
    """Test set_sort_filter with missing name parameter raises BadRequestKeyError."""
    with pytest.raises(Exception):  # Catches BadRequestKeyError or similar
        web_client.post(url_for("analysis.set_sort_filter"))


@pytest.mark.integration
def test_reset_filters_special_invalid_hours(web_client):
    """Test reset_filters_special with invalid hours parameter raises ValueError."""
    with pytest.raises(Exception):  # Catches ValueError or similar
        web_client.get(url_for("analysis.reset_filters_special", hours="invalid"))


@pytest.mark.integration
def test_filter_session_persistence(web_client):
    """Test that filter operations properly maintain session state."""
    # Set initial filters
    filters_data = [{"name": "Description", "inverted": False, "values": ["test"]}]
    
    web_client.post(url_for("analysis.set_filters"), data={
        "filters": json.dumps(filters_data)
    })
    
    # Add another filter
    new_filter = {"name": "Queue", "inverted": True, "values": ["new_queue"]}
    web_client.post(url_for("analysis.add_filter"), data={
        "filter": json.dumps(new_filter)
    })
    
    # Check both filters exist
    with web_client.session_transaction() as sess:
        assert len(sess['filters']) == 2
        filter_names = [f['name'] for f in sess['filters']]
        assert 'Description' in filter_names
        assert 'Queue' in filter_names
    
    # Remove one filter category
    web_client.get(url_for("analysis.remove_filter_category", name="Description"))
    
    # Check only one filter remains
    with web_client.session_transaction() as sess:
        assert len(sess['filters']) == 1
        assert sess['filters'][0]['name'] == 'Queue'


@pytest.mark.integration
def test_pagination_and_checked_reset(web_client):
    """Test that filter operations reset pagination and checked alerts."""
    with web_client.session_transaction() as sess:
        sess['page_offset'] = 50
        sess['checked'] = ['uuid1', 'uuid2', 'uuid3']
    
    # Test that each filter operation resets these values
    operations = [
        lambda: web_client.post(url_for("analysis.set_sort_filter"), data={"name": "test"}),
        lambda: web_client.get(url_for("analysis.reset_filters")),
        lambda: web_client.get(url_for("analysis.reset_filters_special", hours="12")),
        lambda: web_client.post(url_for("analysis.set_filters"), data={"filters": "[]"}),
        lambda: web_client.post(url_for("analysis.add_filter"), data={"filter": '{"name":"test","inverted":false,"values":["test"]}'}),
        lambda: web_client.get(url_for("analysis.remove_filter", name="test", index="0")),
        lambda: web_client.get(url_for("analysis.remove_filter_category", name="test"))
    ]
    
    for operation in operations:
        with web_client.session_transaction() as sess:
            sess['page_offset'] = 50
            sess['checked'] = ['uuid1', 'uuid2']
        
        operation()
        
        with web_client.session_transaction() as sess:
            assert sess['page_offset'] == 0
            assert sess['checked'] == []