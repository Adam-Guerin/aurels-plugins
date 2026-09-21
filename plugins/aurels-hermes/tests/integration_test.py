"""
Integration tests for Hermes plugin structure.
These tests validate plugin structure without requiring Hermes runtime.
Run with: python tests/integration_test.py
"""
import os
import sys
import unittest


class IntegrationTests(unittest.TestCase):
    def test_hermes_plugin_entrypoint(self):
        """Test that the plugin entry point is correctly configured."""
        init_file = os.path.join(os.path.dirname(__file__), "..", "aurels_hermes", "__init__.py")
        plugin_file = os.path.join(os.path.dirname(__file__), "..", "aurels_hermes", "plugin.py")
        
        self.assertTrue(os.path.exists(init_file), f"__init__.py not found at {init_file}")
        self.assertTrue(os.path.exists(plugin_file), f"plugin.py not found at {plugin_file}")
        
        with open(init_file, 'r') as f:
            content = f.read()
            self.assertIn('register', content, "__init__.py should export register function")

    def test_hermes_plugin_manifest(self):
        """Test that the plugin.yaml manifest is correctly configured."""
        manifest_file = os.path.join(os.path.dirname(__file__), "..", "plugin.yaml")
        
        self.assertTrue(os.path.exists(manifest_file), f"plugin.yaml not found at {manifest_file}")
        
        with open(manifest_file, 'r') as f:
            content = f.read()
        
        self.assertIn('name:', content, "Manifest should have name")
        self.assertIn('version:', content, "Manifest should have version")
        self.assertIn('provides_hooks:', content, "Manifest should have provides_hooks")
        self.assertIn('pre_tool_call', content, "Manifest should provide pre_tool_call hook")
        self.assertIn('post_tool_call', content, "Manifest should provide post_tool_call hook")

    def test_hermes_pyproject(self):
        """Test that pyproject.toml has correct entry point."""
        pyproject_file = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
        
        self.assertTrue(os.path.exists(pyproject_file), f"pyproject.toml not found at {pyproject_file}")
        
        with open(pyproject_file, 'r') as f:
            content = f.read()
        
        self.assertIn('aurels_hermes:register', content, "pyproject.toml should have correct entry point")
        self.assertIn('hermes_agent.plugins', content, "pyproject.toml should define hermes entry point group")


if __name__ == "__main__":
    unittest.main()
