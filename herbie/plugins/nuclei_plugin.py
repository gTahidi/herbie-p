"""
Nuclei plugin for advanced vulnerability scanning with Docker support.
"""
from typing import Optional, List, Dict, Any, Union, Annotated
from enum import Enum
import semantic_kernel as sk
from semantic_kernel.functions.kernel_function_decorator import kernel_function
from pydantic import BaseModel, Field
import subprocess
import json
import os
from pathlib import Path
import yaml
import logging
import time
from datetime import datetime
from herbie.utils.logging_config import log_separator

# Get logger
logger = logging.getLogger('herbie.nuclei')

class LogContext:
    """Context manager for structured logging."""
    def __init__(self, context_name: str, level: int = logging.INFO, **kwargs):
        self.context_name = context_name
        self.level = level
        self.kwargs = kwargs
        self.start_time = None
        
    def __enter__(self):
        self.start_time = time.time()
        log_msg = f"Starting {self.context_name}"
        if self.kwargs:
            log_msg += f" with parameters: {json.dumps(self.kwargs, indent=2)}"
        log_separator(logger, log_msg, self.level)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        if exc_type:
            logger.error(f"Error in {self.context_name}: {exc_val}")
            if exc_tb:
                logger.debug(f"Traceback: {exc_tb}")
        log_msg = f"Completed {self.context_name} in {duration:.2f} seconds"
        log_separator(logger, log_msg, self.level)
        
def log_step(step_name: str, level: int = logging.INFO, **kwargs):
    """Decorator for logging function execution with parameters."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with LogContext(step_name, level=level, **kwargs):
                return func(*args, **kwargs)
        return wrapper
    return decorator

# Try importing docker, but don't fail if not available
try:
    import docker
    from docker.errors import DockerException, ImageNotFound, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    log_separator(logger, "Docker SDK not installed. Docker functionality will be disabled.", logging.WARNING)

class InputMode(str, Enum):
    """Supported input modes for nuclei."""
    LIST = "list"
    BURP = "burp"
    JSONL = "jsonl"
    YAML = "yaml"
    OPENAPI = "openapi"
    SWAGGER = "swagger"

class ScanStats:
    """Track scan statistics."""
    def __init__(self):
        self.start_time = time.time()
        self.templates_processed = 0
        self.hosts_scanned = 0
        self.vulnerabilities_found = 0
        self.errors_encountered = 0
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        duration = time.time() - self.start_time
        return {
            "duration_seconds": f"{duration:.2f}",
            "templates_processed": self.templates_processed,
            "hosts_scanned": self.hosts_scanned,
            "vulnerabilities_found": self.vulnerabilities_found,
            "errors_encountered": self.errors_encountered
        }

class NucleiResult(BaseModel):
    """Model for nuclei scan results."""
    template: str
    info: Dict[str, Any]
    host: str
    matched: str
    severity: str
    timestamp: str
    curl_command: Optional[str] = None
    matcher_status: bool = True
    matched_at: Optional[str] = None

class NucleiPlugin:
    """Plugin for advanced vulnerability scanning using nuclei with Docker support."""

    def __init__(self):
        """Initialize the nuclei plugin with Docker if available."""
        self.templates_dir = Path.home() / ".nuclei" / "templates"
        self.use_docker = False
        self.docker_client = None
        self.image_name = "projectdiscovery/nuclei:latest"
        self.stats = None
        
        with LogContext("NucleiPlugin Initialization"):
            try:
                # Create templates directory
                self.templates_dir.mkdir(parents=True, exist_ok=True)
                log_separator(logger, f"Templates directory initialized: {self.templates_dir}", logging.INFO)
                
                # Try to initialize Docker
                if DOCKER_AVAILABLE:
                    try:
                        self.docker_client = docker.from_env()
                        # Test Docker access with a simple operation
                        self.docker_client.ping()
                        self.use_docker = True
                        log_separator(logger, "Docker initialized successfully", logging.INFO)
                        
                        # Check for nuclei image
                        try:
                            self.docker_client.images.get(self.image_name)
                            log_separator(logger, f"Docker image {self.image_name} found", logging.INFO)
                        except ImageNotFound:
                            log_separator(logger, f"Pulling Docker image {self.image_name}", logging.INFO)
                            self.docker_client.images.pull(self.image_name)
                    except DockerException as e:
                        log_separator(logger, f"Docker not accessible: {e}", logging.WARNING)
                
                if not self.use_docker:
                    log_separator(logger, "Docker not available. Please ensure Docker is running and accessible.", logging.WARNING)
                    
            except Exception as e:
                log_separator(logger, f"Failed to initialize plugin: {e}", logging.ERROR)
                raise

    @log_step("Input Validation", level=logging.INFO)
    def _validate_input(self, target: str, input_mode: InputMode = InputMode.LIST) -> bool:
        """Validate the input based on the input mode."""
        try:
            if input_mode == InputMode.LIST:
                targets = target.split(',')
                for t in targets:
                    t = t.strip()
                    if not t:
                        log_separator(logger, f"Empty target found in list: {target}", logging.WARNING)
                        return False
                    log_separator(logger, f"Validated target: {t}", logging.DEBUG)
            elif input_mode in [InputMode.OPENAPI, InputMode.SWAGGER, InputMode.BURP, InputMode.YAML, InputMode.JSONL]:
                if not os.path.isfile(target):
                    log_separator(logger, f"Input file not found: {target}", logging.ERROR)
                    return False
                if not os.access(target, os.R_OK):
                    log_separator(logger, f"Input file not readable: {target}", logging.ERROR)
                    return False
                log_separator(logger, f"Validated input file: {target}", logging.DEBUG)
            return True
        except Exception as e:
            log_separator(logger, f"Input validation error: {e}", logging.ERROR)
            return False

    @log_step("Nuclei Scan Execution", level=logging.INFO)
    def _run_nuclei_scan(self, cmd: List[str], volumes: Dict[str, Dict[str, str]] = None) -> tuple[List[NucleiResult], List[str]]:
        """Run nuclei scan using Docker."""
        results = []
        errors = []
        self.stats = ScanStats()
        
        try:
            if not self.use_docker:
                raise DockerException("Docker is not available")
            
            # Default volumes
            if volumes is None:
                volumes = {
                    str(self.templates_dir): {
                        'bind': '/root/.nuclei/templates',
                        'mode': 'rw'
                    }
                }
            
            log_separator(logger, "Starting Docker container with following configuration:", logging.INFO)
            log_separator(logger, f"Image: {self.image_name}", logging.INFO)
            log_separator(logger, f"Command: nuclei {' '.join(cmd)}", logging.INFO)
            log_separator(logger, f"Volumes: {json.dumps(volumes, indent=2)}", logging.INFO)
            
            # Run nuclei in Docker
            container = self.docker_client.containers.run(
                self.image_name,
                command=cmd,
                remove=True,
                detach=True,
                volumes=volumes
            )
            
            log_separator(logger, f"Container started: {container.id}", logging.INFO)
            
            # Stream and decode logs manually
            log_separator(logger, "Processing scan output...", logging.INFO)
            for log_bytes in container.logs(stream=True):
                try:
                    log_line = log_bytes.decode('utf-8').strip()
                    if log_line:
                        if log_line.startswith('{'):
                            try:
                                result = json.loads(log_line)
                                results.append(NucleiResult(**result))
                                self.stats.vulnerabilities_found += 1
                                
                                # Log vulnerability details
                                log_separator(logger, f"Vulnerability found:", logging.INFO)
                                log_separator(logger, f"  Template: {result.get('template')}", logging.INFO)
                                log_separator(logger, f"  Host: {result.get('host')}", logging.INFO)
                                log_separator(logger, f"  Severity: {result.get('severity')}", logging.INFO)
                                
                            except json.JSONDecodeError:
                                log_separator(logger, f"Failed to parse JSON output: {log_line}", logging.WARNING)
                                errors.append(log_line)
                                self.stats.errors_encountered += 1
                        else:
                            # Process non-JSON output for statistics
                            if "templates processed" in log_line.lower():
                                self.stats.templates_processed += 1
                            elif "hosts scanned" in log_line.lower():
                                self.stats.hosts_scanned += 1
                            log_separator(logger, f"Non-JSON output: {log_line}", logging.DEBUG)
                except Exception as e:
                    log_separator(logger, f"Error processing log line: {str(e)}", logging.ERROR)
                    errors.append(f"Error processing log line: {str(e)}")
                    self.stats.errors_encountered += 1

            # Wait for container to complete and check exit code
            result = container.wait()
            exit_code = result.get('StatusCode', -1)
            
            if exit_code != 0:
                error_msg = result.get('Error', {}).get('Message', f"Container exited with code {exit_code}")
                log_separator(logger, f"Scan failed: {error_msg}", logging.ERROR)
                errors.append(error_msg)
                self.stats.errors_encountered += 1
            else:
                log_separator(logger, "Scan completed successfully", logging.INFO)
            
            # Log final statistics
            stats_dict = self.stats.to_dict()
            log_separator(logger, "Scan Statistics:", logging.INFO)
            for key, value in stats_dict.items():
                log_separator(logger, f"  {key}: {value}", logging.INFO)
                
        except DockerException as e:
            log_separator(logger, f"Docker error: {str(e)}", logging.ERROR)
            errors.append(f"Docker error: {str(e)}")
            self.stats.errors_encountered += 1
        except Exception as e:
            log_separator(logger, f"Unexpected error: {str(e)}", logging.ERROR)
            errors.append(f"Unexpected error: {str(e)}")
            self.stats.errors_encountered += 1
            
        return results, errors

    @kernel_function(description="Run a nuclei scan on a target")
    @log_step("Nuclei Scan")
    def nuclei_scan(
        self,
        target: Annotated[str, "The target URL, file, or comma-separated list of targets"],
        input_mode: Annotated[str, "Input mode (list, burp, jsonl, yaml, openapi, swagger)"] = "list",
        severity: Annotated[str, "Severity level (low, medium, high, critical)"] = "medium",
        tags: Annotated[str, "Comma-separated list of tags to include"] = "",
        exclude_tags: Annotated[str, "Comma-separated list of tags to exclude"] = "",
        vars: Annotated[str, "Comma-separated key=value pairs for template variables"] = "",
        required_only: Annotated[bool, "Use only required fields in input format"] = False,
        skip_format_validation: Annotated[bool, "Skip format validation"] = False
    ) -> str:
        """Run a nuclei scan on a target with support for various input formats."""
        log_separator(logger, f"Starting nuclei scan on {target}", logging.INFO)
        logger.debug(f"Scan parameters - Mode: {input_mode}, Severity: {severity}, Tags: {tags}, "
                    f"Exclude Tags: {exclude_tags}, Vars: {vars}")

        try:
            # Validate input mode
            try:
                input_mode_enum = InputMode(input_mode.lower())
            except ValueError:
                error_msg = f"Invalid input mode: {input_mode}. Supported modes: {', '.join([m.value for m in InputMode])}"
                log_separator(logger, error_msg, logging.ERROR)
                return error_msg

            # Validate input
            if not self._validate_input(target, input_mode_enum):
                error_msg = "Invalid input. Please check logs for details."
                log_separator(logger, error_msg, logging.ERROR)
                return error_msg

            # Build command list
            cmd = []
            
            # Add target specification
            if input_mode_enum == InputMode.LIST:
                cmd.extend(["-target", target])  # Using -target instead of -u
            else:
                cmd.extend(["-l", target, "-im", input_mode_enum.value])

            # Add common parameters
            cmd.extend(["-json-output"])  # Using -json-output instead of -json
            
            if severity:
                cmd.extend(["-severity", severity])
            if tags:
                cmd.extend(["-tags", tags])
            if exclude_tags:
                cmd.extend(["-exclude-tags", exclude_tags])
            if vars:
                cmd.extend(["-var", vars])  # Using -var instead of -vars
            if required_only:
                cmd.append("-ro")
            if skip_format_validation:
                cmd.append("-sfv")

            logger.debug(f"Command: nuclei {' '.join(cmd)}")

            # Set up volumes for file-based inputs
            volumes = {str(self.templates_dir): {'bind': '/root/.nuclei/templates', 'mode': 'rw'}}
            if input_mode_enum != InputMode.LIST:
                # Add volume mapping for input file
                input_file = Path(target).resolve()
                volumes[str(input_file.parent)] = {'bind': '/input', 'mode': 'ro'}
                # Update command to use mounted path
                cmd = [arg.replace(str(input_file), f"/input/{input_file.name}") for arg in cmd]

            results, errors = self._run_nuclei_scan(cmd, volumes)

            # Format results
            if not results:
                if errors:
                    error_msg = "No valid results found. Errors encountered:\n" + "\n".join(errors)
                    log_separator(logger, error_msg, logging.WARNING)
                    return error_msg
                log_separator(logger, "No vulnerabilities found.", logging.INFO)
                return "No vulnerabilities found."

            # Format the results
            formatted_output = "Scan Results:\n\n"
            for result in results:
                formatted_output += f"Template: {result.template}\n"
                formatted_output += f"Host: {result.host}\n"
                formatted_output += f"Severity: {result.severity}\n"
                formatted_output += f"Matched: {result.matched}\n"
                if result.curl_command:
                    formatted_output += f"CURL Command: {result.curl_command}\n"
                formatted_output += f"Timestamp: {result.timestamp}\n"
                formatted_output += "-" * 50 + "\n"

            log_separator(logger, "Scan completed successfully", logging.INFO)
            logger.debug(f"Formatted output: {formatted_output}")
            return formatted_output

        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            log_separator(logger, error_msg, logging.ERROR)
            return error_msg

    @kernel_function(description="Upload a custom nuclei template")
    @log_step("Template Upload")
    def upload_template(
        self,
        content: Annotated[str, "Template content in YAML format"],
        category: Annotated[str, "Template category"] = "custom"
    ) -> str:
        """Upload a custom nuclei template."""
        log_separator(logger, "Uploading nuclei template", logging.INFO)
        logger.debug(f"Template category: {category}")

        try:
            # Validate YAML content
            try:
                template = yaml.safe_load(content)
                if not isinstance(template, dict):
                    error_msg = "Invalid template format: content must be a YAML dictionary"
                    log_separator(logger, error_msg, logging.ERROR)
                    return error_msg
                
                # Basic template validation
                required_fields = ['id', 'info', 'requests']
                missing_fields = [field for field in required_fields if field not in template]
                if missing_fields:
                    error_msg = f"Invalid template: missing required fields: {', '.join(missing_fields)}"
                    log_separator(logger, error_msg, logging.ERROR)
                    return error_msg
                
            except yaml.YAMLError as e:
                error_msg = f"Invalid YAML format: {str(e)}"
                log_separator(logger, error_msg, logging.ERROR)
                return error_msg

            # Create category directory if it doesn't exist
            category_dir = self.templates_dir / category
            category_dir.mkdir(parents=True, exist_ok=True)

            # Generate filename from template ID
            template_id = template['id']
            filename = f"{template_id}.yaml"
            template_path = category_dir / filename

            # Write template file
            try:
                with open(template_path, 'w') as f:
                    yaml.dump(template, f)
                success_msg = f"Template uploaded successfully to {template_path}"
                log_separator(logger, success_msg, logging.INFO)
                return success_msg
            except Exception as e:
                error_msg = f"Failed to write template: {str(e)}"
                log_separator(logger, error_msg, logging.ERROR)
                return error_msg

        except Exception as e:
            error_msg = f"Error uploading template: {str(e)}"
            log_separator(logger, error_msg, logging.ERROR)
            return error_msg

    @kernel_function(description="List available nuclei templates")
    @log_step("Template Listing")
    def list_templates(
        self,
        category: Annotated[str, "Template category to list"] = ""
    ) -> str:
        """List available nuclei templates."""
        log_separator(logger, "Listing nuclei templates", logging.INFO)
        logger.debug(f"Category filter: {category}")

        try:
            templates = []
            search_dir = self.templates_dir / category if category else self.templates_dir
            
            if not search_dir.exists():
                error_msg = f"Category directory not found: {search_dir}"
                log_separator(logger, error_msg, logging.WARNING)
                return f"Category {category} not found"

            log_separator(logger, f"Searching for templates in: {search_dir}", logging.INFO)
            for template_file in search_dir.rglob("*.yaml"):
                try:
                    logger.debug(f"Processing template file: {template_file}")
                    with open(template_file) as f:
                        template = yaml.safe_load(f)
                        templates.append({
                            "id": template.get("id", "unknown"),
                            "name": template.get("info", {}).get("name", "unknown"),
                            "severity": template.get("info", {}).get("severity", "unknown"),
                            "path": str(template_file.relative_to(self.templates_dir))
                        })
                        logger.debug(f"Template loaded: {templates[-1]}")
                except Exception as e:
                    log_separator(logger, f"Error processing template {template_file}: {e}", logging.ERROR)
                    continue

            if not templates:
                log_separator(logger, "No templates found", logging.INFO)
                return "No templates found"

            output = ["Available Templates:"]
            for template in templates:
                output.append(f"\nID: {template['id']}")
                output.append(f"Name: {template['name']}")
                output.append(f"Severity: {template['severity']}")
                output.append(f"Path: {template['path']}")
                output.append("-" * 40)

            formatted_output = "\n".join(output)
            log_separator(logger, f"Found {len(templates)} templates", logging.INFO)
            logger.debug(f"Formatted output: {formatted_output}")
            return formatted_output

        except Exception as e:
            error_msg = f"Error listing templates: {str(e)}"
            log_separator(logger, error_msg, logging.ERROR)
            return error_msg
