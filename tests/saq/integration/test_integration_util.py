import os
import pytest

from saq.integration.integration_util import (
    get_integration_var_base_dir,
    get_integration_name_from_path,
    get_integration_path_from_name
)


@pytest.mark.unit
class TestIntegrationUtil:
    
    def test_get_integration_var_base_dir(self):
        """Test that get_integration_var_base_dir returns correct path structure."""
        result = get_integration_var_base_dir()
        
        # Should end with 'var/integrations'
        assert result.endswith(os.path.join("var", "integrations"))
        
        # Should be an absolute path
        assert os.path.isabs(result)
    
    def test_get_integration_name_from_path_with_simple_path(self):
        """Test get_integration_name_from_path with simple directory name."""
        test_path = "/path/to/test_integration"
        result = get_integration_name_from_path(test_path)
        
        assert result == "test_integration"
    
    def test_get_integration_name_from_path_with_nested_path(self):
        """Test get_integration_name_from_path with nested directory structure."""
        test_path = "/very/deep/nested/path/my_integration"
        result = get_integration_name_from_path(test_path)
        
        assert result == "my_integration"
    
    def test_get_integration_name_from_path_with_trailing_slash(self):
        """Test get_integration_name_from_path with trailing slash."""
        test_path = "/path/to/integration_name/"
        with pytest.raises(ValueError):
            get_integration_name_from_path(test_path)
    
    def test_get_integration_name_from_path_with_relative_path(self):
        """Test get_integration_name_from_path with relative path."""
        test_path = "relative/path/integration"
        result = get_integration_name_from_path(test_path)
        
        assert result == "integration"
    
    def test_get_integration_name_from_path_with_single_directory(self):
        """Test get_integration_name_from_path with just a directory name."""
        test_path = "single_integration"
        result = get_integration_name_from_path(test_path)
        
        assert result == "single_integration"
    
    def test_get_integration_path_from_name(self):
        """Test get_integration_path_from_name returns correct integration path."""
        test_name = "test_integration"
        result = get_integration_path_from_name(test_name)
        
        # Should end with 'integrations/test_integration'
        assert result.endswith(os.path.join("integrations", test_name))
        
        # Should be an absolute path
        assert os.path.isabs(result)
    
    def test_get_integration_path_from_name_with_special_characters(self):
        """Test get_integration_path_from_name with names containing special characters."""
        test_cases = [
            "integration_with_underscores",
            "integration-with-dashes", 
            "integration.with.dots",
            "integration123"
        ]
        
        for test_name in test_cases:
            result = get_integration_path_from_name(test_name)
            
            # Should end with 'integrations/{name}'
            assert result.endswith(os.path.join("integrations", test_name))
            
            # Should be absolute path
            assert os.path.isabs(result)
    
    def test_integration_functions_consistency(self):
        """Test that the integration functions work consistently together."""
        test_integration_name = "consistent_test"
        
        # Create a fake path with the integration name
        fake_path = f"/fake/path/{test_integration_name}"
        
        # Test round-trip consistency
        name_from_path = get_integration_name_from_path(fake_path)
        path_from_name = get_integration_path_from_name(name_from_path)
        
        # The name should be preserved
        assert name_from_path == test_integration_name
        
        # The path should end with the integration name
        assert path_from_name.endswith(test_integration_name)
    
    def test_path_handling_edge_cases(self):
        """Test edge cases for path handling."""
        # Empty string should raise ValueError
        with pytest.raises(ValueError):
            get_integration_name_from_path("")
        
        # Root path
        with pytest.raises(ValueError):
            get_integration_name_from_path("/")
        
        # Path with only slashes
        with pytest.raises(ValueError):
            get_integration_name_from_path("//")
    
    @pytest.mark.parametrize(
        "test_path,expected",
        [
            ("/path/to/my_integration", "my_integration"),
            ("/path/to/my_integration/", pytest.raises(ValueError)),
            ("/path/to//my_integration", "my_integration"),
            ("/path/to/../to/my_integration", "my_integration"),
        ]
    )
    def test_path_normalization(self, test_path, expected):
        """Test that paths are handled correctly regardless of format."""
        if isinstance(expected, str):
            assert get_integration_name_from_path(test_path) == expected
        else:
            with expected:
                get_integration_name_from_path(test_path)