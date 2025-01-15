from setuptools import setup, find_packages

setup(
    name="herbie",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "semantic-kernel>=0.3.14.dev0",
        "python-dotenv>=1.0.0",
        "aiohttp>=3.9.1",
        "pydantic>=2.5.3",
        "python-nmap>=0.7.1",
        "beautifulsoup4>=4.12.2",
        "pyyaml>=6.0.1",
        "fabric>=3.2.2",
        "requests>=2.31.0",
        "rich>=13.7.0",
        "instructor>=0.4.8",
        "openai>=1.6.1",
        "tiktoken>=0.5.2"
    ],
    author="Daniel",
    author_email="ddaniel@ujaoteh.com",
    description="A security-focused copilot using Semantic Kernel",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
)
