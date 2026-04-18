from setuptools import setup, find_packages

setup(
    name="aso",
    version="1.0.0",
    description="Automated Security Operator — AI Pentest Agent for Bug Bounty",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "anthropic>=0.40.0",
        "httpx>=0.27.0",
        "aiofiles>=23.2.1",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
        "click>=8.1.7",
        "jinja2>=3.1.4",
        "python-dotenv>=1.0.1",
        "beautifulsoup4>=4.12.3",
        "requests>=2.32.0",
    ],
    entry_points={
        "console_scripts": [
            "aso=main:cli",
        ],
    },
)
