import unittest

class TestImportSanity(unittest.TestCase):
    def test_tools_imports(self):
        # If any tool has a missing typing import (Optional etc), this will explode immediately.
        import tools.semantic_validate  # noqa: F401
        import tools.validate_all       # noqa: F401
        import tools.validate_schemas   # noqa: F401

if __name__ == "__main__":
    unittest.main()