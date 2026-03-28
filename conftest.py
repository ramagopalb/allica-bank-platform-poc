# conftest.py — shared pytest configuration for Allica Bank Platform POC
import sys
import os

# Add the POC_Project root to sys.path so devops_platform can be imported
sys.path.insert(0, os.path.dirname(__file__))
