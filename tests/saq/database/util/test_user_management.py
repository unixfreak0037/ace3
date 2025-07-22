import pytest
from werkzeug.security import check_password_hash

from saq.constants import QUEUE_DEFAULT
from saq.database.model import User
from saq.database.pool import get_db
from saq.database.util.user_management import add_user, delete_user


@pytest.mark.integration
def test_add_user_success():
    """Test successfully adding a new user to the database."""
    username = "testuser123"
    email = "testuser123@example.com"
    display_name = "Test User"
    password = "testpassword123"
    queue = "test_queue"
    timezone = "America/New_York"
    
    # Add the user
    user = add_user(
        username=username,
        email=email,
        display_name=display_name,
        password=password,
        queue=queue,
        timezone=timezone
    )
    
    # Verify user was created and returned
    assert user is not None
    assert isinstance(user, User)
    assert user.username == username
    assert user.email == email
    assert user.display_name == display_name
    assert user.queue == queue
    assert user.timezone == timezone
    assert user.id is not None
    
    # Verify password was hashed correctly
    assert user.verify_password(password)
    assert user.password_hash is not None
    assert user.password_hash != password  # Password should be hashed
    
    # Verify user exists in database
    db = get_db()
    db_user = db.query(User).filter(User.username == username).first()
    assert db_user is not None
    assert db_user.id == user.id
    
    # Cleanup
    delete_user(username)


@pytest.mark.integration
def test_add_user_with_defaults():
    """Test adding a user with default queue and timezone values."""
    username = "defaultuser"
    email = "defaultuser@example.com"
    display_name = "Default User"
    password = "password123"
    
    # Add user without specifying queue and timezone (should use defaults)
    user = add_user(
        username=username,
        email=email,
        display_name=display_name,
        password=password
    )
    
    assert user.username == username
    assert user.email == email
    assert user.display_name == display_name
    assert user.queue == QUEUE_DEFAULT
    assert user.timezone == "Etc/UTC"
    assert user.verify_password(password)
    
    # Cleanup
    delete_user(username)


@pytest.mark.integration
def test_add_user_minimal_params():
    """Test adding a user with only required parameters."""
    username = "minimaluser"
    email = "minimaluser@example.com"
    display_name = "Minimal User"
    password = "minimalpass"
    
    user = add_user(username, email, display_name, password)
    
    assert user.username == username
    assert user.email == email
    assert user.display_name == display_name
    assert user.verify_password(password)
    
    # Cleanup
    delete_user(username)


@pytest.mark.integration
def test_add_user_password_hashing():
    """Test that passwords are properly hashed and not stored in plaintext."""
    username = "hashuser"
    email = "hashuser@example.com"
    display_name = "Hash User"
    password = "plaintext_password"
    
    user = add_user(username, email, display_name, password)
    
    # Password should be hashed
    assert user.password_hash != password
    assert len(user.password_hash) > len(password)
    assert user.verify_password(password)
    assert not user.verify_password("wrong_password")
    
    # Cleanup
    delete_user(username)


@pytest.mark.integration
def test_delete_user_success():
    """Test successfully deleting an existing user."""
    username = "deleteuser"
    email = "deleteuser@example.com"
    display_name = "Delete User"
    password = "deletepass"
    
    # First add a user
    user = add_user(username, email, display_name, password)
    user_id = user.id
    
    # Verify user exists
    db = get_db()
    assert db.query(User).filter(User.id == user_id).first() is not None
    
    # Delete the user
    result = delete_user(username)
    
    # Verify deletion was successful
    assert result is True
    
    # Verify user no longer exists in database
    assert db.query(User).filter(User.id == user_id).first() is None
    assert db.query(User).filter(User.username == username).first() is None


@pytest.mark.integration
def test_delete_user_nonexistent():
    """Test deleting a user that doesn't exist."""
    nonexistent_username = "nonexistentuser123"
    
    # Ensure user doesn't exist
    db = get_db()
    assert db.query(User).filter(User.username == nonexistent_username).first() is None
    
    # Try to delete nonexistent user
    result = delete_user(nonexistent_username)
    
    # Should return False
    assert result is False


@pytest.mark.integration
def test_add_delete_user_lifecycle():
    """Test the complete lifecycle of adding and then deleting a user."""
    username = "lifecycleuser"
    email = "lifecycleuser@example.com"
    display_name = "Lifecycle User"
    password = "lifecyclepass"
    
    # Initially user should not exist
    db = get_db()
    assert db.query(User).filter(User.username == username).first() is None
    
    # Add user
    user = add_user(username, email, display_name, password)
    assert user is not None
    user_id = user.id
    
    # User should exist
    assert db.query(User).filter(User.id == user_id).first() is not None
    
    # Delete user
    result = delete_user(username)
    assert result is True
    
    # User should no longer exist
    assert db.query(User).filter(User.id == user_id).first() is None


@pytest.mark.integration
def test_add_user_duplicate_username():
    """Test adding a user with a username that already exists."""
    username = "duplicateuser"
    email1 = "user1@example.com"
    email2 = "user2@example.com"
    display_name = "Duplicate User"
    password = "password123"
    
    # Add first user
    user1 = add_user(username, email1, display_name, password)
    assert user1 is not None
    
    try:
        # Try to add second user with same username (should fail)
        with pytest.raises(Exception):  # Should raise database integrity error
            add_user(username, email2, display_name, password)

        get_db().rollback()

    finally:
        # Cleanup
        delete_user(username)


@pytest.mark.integration
def test_add_user_duplicate_email():
    """Test adding a user with an email that already exists."""
    username1 = "user1"
    username2 = "user2"
    email = "duplicate@example.com"
    display_name = "User"
    password = "password123"
    
    # Add first user
    user1 = add_user(username1, email, display_name, password)
    assert user1 is not None
    
    try:
        # Try to add second user with same email (should fail)
        with pytest.raises(Exception):  # Should raise database integrity error
            add_user(username2, email, display_name, password)

        get_db().rollback()

    finally:
        # Cleanup
        delete_user(username1)


@pytest.mark.integration
def test_delete_user_with_relationships():
    """Test deleting a user that might have related records (comments, etc)."""
    username = "relationuser"
    email = "relationuser@example.com"
    display_name = "Relation User"
    password = "password123"
    
    # Add user
    user = add_user(username, email, display_name, password)
    assert user is not None
    
    # Note: In a real scenario, the user might have comments, remediations, etc.
    # For this test, we're just verifying the basic delete works
    # More complex relationship testing would require setting up those relationships
    
    # Delete user
    result = delete_user(username)
    assert result is True
    
    # Verify deletion
    db = get_db()
    assert db.query(User).filter(User.username == username).first() is None