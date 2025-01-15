# Herbie - Security Testing Copilot

Herbie is an advanced security testing copilot that automates and enhances security scanning operations. It integrates with popular security tools like Nuclei and provides an intelligent interface for security testing workflows.

## Features

- **Advanced Scanning Capabilities**
  - Nuclei integration for vulnerability scanning
  - Automated template management
  - Smart scan configuration

- **Docker Integration**
  - Persistent container management
  - Automated template updates
  - Efficient resource utilization

- **Comprehensive Reporting**
  - Detailed scan results
  - JSON output support
  - Vulnerability statistics

## Prerequisites

- Python 3.8+
- Docker
- Docker user permissions (user should be in docker group)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/herbie-p.git
cd herbie-p
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Usage

### Basic Usage

```python
from herbie.plugins.nuclei_plugin import NucleiPlugin

# Initialize the plugin
nuclei = NucleiPlugin()

# Run a scan
results = nuclei.nuclei_scan(
    target="example.com",
    severity="medium",
    tags="cve"
)
```

### Advanced Configuration

```python
# Custom template configuration
results = nuclei.nuclei_scan(
    target="example.com",
    severity="high",
    tags="cve,rce",
    vars="port=443,ssl=true"
)
```

## Security Considerations

- Never commit sensitive information to the repository
- Keep API keys and credentials in `.env` file
- Review scan targets and permissions before execution
- Avoid running scans against unauthorized targets
- Handle scan results with appropriate confidentiality

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Project Discovery](https://projectdiscovery.io/) for Nuclei
- [Docker](https://www.docker.com/) for containerization support
- All contributors and security researchers

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

---

**Disclaimer**: This tool is for security testing purposes only. Always ensure you have proper authorization before scanning any targets.