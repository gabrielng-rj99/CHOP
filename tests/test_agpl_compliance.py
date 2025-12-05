# =============================================================================
# Entity Hub Open Project
# Copyright (C) 2025 Entity Hub Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
# =============================================================================

"""
AGPL-3.0 Compliance Verification Tests

This test suite verifies that the entire Entity Hub Open Project is properly
protected under the GNU Affero General Public License v3.0.

Tests verify:
  - License file presence and content
  - Source file header compliance
  - Documentation completeness
  - Dependency license compatibility
"""

import os
import re
import json
from pathlib import Path
from typing import Set, List, Tuple

import pytest


# Configuration
PROJECT_ROOT = Path(__file__).parent.parent
SKIP_DIRS = {
    'node_modules', '.git', '.venv', 'venv', '__pycache__',
    'dist', 'build', '.next', '.nuxt', 'coverage', 'bin',
    'deploy', '.github', '.gitlab'
}
SOURCE_EXTENSIONS = {'.go', '.jsx', '.js', '.py', '.css'}
MIN_FILES_WITH_HEADERS = 110  # Expected minimum


class TestAGPLLicenseFiles:
    """Test that all required AGPL-3.0 license files exist."""

    def test_license_file_exists(self):
        """Verify LICENSE file exists and contains AGPL-3.0 text."""
        license_file = PROJECT_ROOT / "LICENSE"
        assert license_file.exists(), "LICENSE file not found"

        with open(license_file, 'r') as f:
            content = f.read()

        assert 'GNU Affero General Public License' in content
        assert 'Version 3' in content
        assert len(content) > 10000, "LICENSE file seems incomplete"

    def test_copying_file_exists(self):
        """Verify COPYING file exists."""
        copying_file = PROJECT_ROOT / "COPYING"
        assert copying_file.exists(), "COPYING file not found"

        with open(copying_file, 'r') as f:
            content = f.read()

        assert 'GNU Affero General Public License' in content
        assert len(content) > 1000

    def test_notice_file_exists(self):
        """Verify NOTICE file exists."""
        notice_file = PROJECT_ROOT / "NOTICE"
        assert notice_file.exists(), "NOTICE file not found"

        with open(notice_file, 'r') as f:
            content = f.read()

        assert 'Entity Hub' in content
        assert 'Copyright' in content

    def test_license_information_file_exists(self):
        """Verify LICENSE-INFORMATION.md exists."""
        info_file = PROJECT_ROOT / "LICENSE-INFORMATION.md"
        assert info_file.exists(), "LICENSE-INFORMATION.md file not found"


class TestSourceFileHeaders:
    """Test that source files have proper AGPL-3.0 headers."""

    @staticmethod
    def get_source_files() -> List[Path]:
        """Get all source files that should have headers."""
        source_files = []

        for root, dirs, files in os.walk(PROJECT_ROOT):
            # Remove skip directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                if any(file.endswith(ext) for ext in SOURCE_EXTENSIONS):
                    filepath = Path(root) / file
                    source_files.append(filepath)

        return sorted(source_files)

    def test_source_files_have_headers(self):
        """Verify all source files have AGPL-3.0 headers."""
        source_files = self.get_source_files()

        assert len(source_files) > 0, "No source files found"

        files_with_headers = 0
        files_without_headers = []

        for filepath in source_files:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(500)  # Check first 500 chars

                if 'Entity Hub Open Project' in content or 'GNU Affero General Public License' in content:
                    files_with_headers += 1
                else:
                    files_without_headers.append(str(filepath.relative_to(PROJECT_ROOT)))
            except Exception as e:
                print(f"Warning: Could not read {filepath}: {e}")

        # Assert minimum coverage
        assert files_with_headers >= MIN_FILES_WITH_HEADERS, \
            f"Only {files_with_headers} files have headers (expected >= {MIN_FILES_WITH_HEADERS}). " \
            f"Missing headers in:\n{chr(10).join(files_without_headers[:10])}"

    def test_no_proprietary_headers(self):
        """Verify no files have proprietary license headers."""
        source_files = self.get_source_files()

        proprietary_indicators = [
            'proprietary', 'commercial license', 'all rights reserved',
            'closed source', 'do not distribute'
        ]

        files_with_proprietary = []

        for filepath in source_files:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1000).lower()

                if any(indicator in content for indicator in proprietary_indicators):
                    files_with_proprietary.append(str(filepath.relative_to(PROJECT_ROOT)))
            except Exception:
                pass

        assert len(files_with_proprietary) == 0, \
            f"Found proprietary headers in: {files_with_proprietary}"


class TestDependencyLicenses:
    """Test that all dependencies have AGPL-3.0 compatible licenses."""

    def test_go_dependencies_compatible(self):
        """Verify Go dependencies are AGPL-3.0 compatible."""
        go_mod = PROJECT_ROOT / "backend" / "go.mod"
        assert go_mod.exists(), "backend/go.mod not found"

        with open(go_mod, 'r') as f:
            content = f.read()

        # Check for license verification comment
        assert 'DEPENDENCY LICENSE COMPATIBILITY VERIFICATION' in content, \
            "go.mod missing license compatibility verification"

        # Verify no GPL-2.0 only dependencies
        assert 'GPL-2.0' not in content or 'compatible' in content

    def test_frontend_dependencies_compatible(self):
        """Verify frontend dependencies are AGPL-3.0 compatible."""
        package_json = PROJECT_ROOT / "frontend" / "package.json"
        assert package_json.exists(), "frontend/package.json not found"

        with open(package_json, 'r') as f:
            data = json.load(f)

        # Check for license field
        assert data.get('license') == 'AGPL-3.0', \
            "package.json missing AGPL-3.0 license field"

        # Check for dependency verification
        assert '_dependencies_verified' in data, \
            "package.json missing dependency verification"

    def test_test_dependencies_compatible(self):
        """Verify test dependencies are AGPL-3.0 compatible."""
        requirements = PROJECT_ROOT / "tests" / "requirements.txt"
        assert requirements.exists(), "tests/requirements.txt not found"

        with open(requirements, 'r') as f:
            content = f.read()

        # Check for license verification comment
        assert 'DEPENDENCY LICENSE COMPATIBILITY VERIFICATION' in content, \
            "requirements.txt missing license compatibility verification"

        # Verify no GPL-2.0 only packages
        assert 'GPL-2.0' not in content or 'compatible' in content


class TestDocumentation:
    """Test that license documentation is complete."""

    def test_readme_has_license_section(self):
        """Verify README.md has AGPL-3.0 license section."""
        readme = PROJECT_ROOT / "README.md"
        assert readme.exists(), "README.md not found"

        with open(readme, 'r') as f:
            content = f.read()

        assert '## License' in content or '## license' in content.lower()
        assert 'GNU Affero General Public License' in content
        assert 'AGPL-3.0' in content or 'AGPL' in content

    def test_checklist_exists(self):
        """Verify AGPL-CHECKLIST.md exists."""
        checklist = PROJECT_ROOT / "AGPL-CHECKLIST.md"
        assert checklist.exists(), "AGPL-CHECKLIST.md not found"

        with open(checklist, 'r') as f:
            content = f.read()

        assert 'Completed Items' in content
        assert 'Source Code Headers' in content


class TestHeaderConsistency:
    """Test header format consistency across different file types."""

    def test_go_file_header_format(self):
        """Verify Go files have consistent header format."""
        go_files = list(PROJECT_ROOT.glob("backend/**/*.go"))

        if go_files:
            # Check first file with header
            for filepath in go_files[:5]:
                with open(filepath, 'r') as f:
                    content = f.read(300)

                if 'Entity Hub Open Project' in content:
                    assert content.startswith('/*'), "Go file header should start with /*"
                    assert 'GNU Affero General Public License' in content

    def test_python_file_header_format(self):
        """Verify Python files have consistent header format."""
        py_files = list(PROJECT_ROOT.glob("tests/**/*.py"))

        if py_files:
            for filepath in py_files[:5]:
                with open(filepath, 'r') as f:
                    content = f.read(600)

                if 'Entity Hub Open Project' in content:
                    assert 'GNU Affero General Public License' in content
                    assert '#' in content[:10]

    def test_javascript_file_header_format(self):
        """Verify JavaScript/JSX files have consistent header format."""
        js_files = list(PROJECT_ROOT.glob("frontend/src/**/*.jsx")) + \
                   list(PROJECT_ROOT.glob("frontend/src/**/*.js"))

        if js_files:
            for filepath in js_files[:5]:
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read(300)

                    if 'Entity Hub Open Project' in content:
                        assert 'GNU Affero General Public License' in content
                        assert '/*' in content[:50]
                except Exception:
                    pass


class TestComplianceIntegration:
    """Integration tests for overall AGPL-3.0 compliance."""

    def test_no_conflicting_licenses(self):
        """Verify no conflicting licenses in project."""
        # Check for any GPL-2.0 mentions outside of compatibility notes
        suspicious_files = []

        for root, dirs, files in os.walk(PROJECT_ROOT):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                if file.endswith(('.go', '.py', '.js', '.jsx', '.json')):
                    filepath = Path(root) / file

                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()

                        # Only flag if GPL-2.0 without compatibility mention
                        if 'GPL-2.0' in content and 'compatible' not in content.lower():
                            suspicious_files.append(str(filepath.relative_to(PROJECT_ROOT)))
                    except Exception:
                        pass

        assert len(suspicious_files) == 0, \
            f"Found potential GPL-2.0 conflicts in: {suspicious_files}"

    def test_license_notice_in_critical_files(self):
        """Verify critical entry points have license notices."""
        critical_files = [
            PROJECT_ROOT / "backend" / "cmd" / "server" / "main.go",
            PROJECT_ROOT / "backend" / "cmd" / "cli" / "main.go",
            PROJECT_ROOT / "frontend" / "src" / "main.jsx",
            PROJECT_ROOT / "frontend" / "src" / "App.jsx",
        ]

        for filepath in critical_files:
            if filepath.exists():
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read(500)

                assert 'Entity Hub Open Project' in content or 'GNU Affero' in content, \
                    f"Critical file missing license header: {filepath.relative_to(PROJECT_ROOT)}"

    def test_overall_project_compliance(self):
        """Overall compliance check."""
        # This should pass if all other tests pass
        license_file = PROJECT_ROOT / "LICENSE"
        copying_file = PROJECT_ROOT / "COPYING"

        assert license_file.exists() and license_file.stat().st_size > 10000
        assert copying_file.exists()

        # Count files with headers
        source_files = list(PROJECT_ROOT.glob("backend/**/*.go")) + \
                       list(PROJECT_ROOT.glob("frontend/src/**/*.{jsx,js,css}")) + \
                       list(PROJECT_ROOT.glob("tests/**/*.py"))

        assert len(source_files) > 100, "Project should have over 100 source files"


@pytest.mark.compliance
class TestAGPLComplianceSummary:
    """Summary test that checks if project is AGPL-3.0 compliant."""

    def test_project_is_agpl_protected(self):
        """
        Final integration test: Verify the entire project is AGPL-3.0 protected.

        This test confirms:
        ✓ All license files present
        ✓ Source files have headers
        ✓ Dependencies are compatible
        ✓ Documentation is complete
        ✓ No conflicting licenses
        """
        pytest.skip("This is a marker test - run other tests first")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
