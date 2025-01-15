"""
Nuclei plugin for advanced vulnerability scanning.
"""
from typing import Optional, List, Dict, Any, Union, Annotated
import semantic_kernel as sk
from semantic_kernel.functions.kernel_function_decorator import kernel_function
from pydantic import BaseModel, Field
import subprocess
import json
import os
from pathlib import Path
import yaml
import logging
from herbie.utils.logging_config import log_separator

# Get logger
logger = logging.getLogger('herbie.nuclei')

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
    """Plugin for advanced vulnerability scanning using nuclei."""

    def __init__(self):
        """Initialize the nuclei plugin."""
        logger.info("Initializing NucleiPlugin")
        self.nuclei_path = "nuclei"  # Assuming nuclei is in PATH
        self.templates_dir = Path.home() / ".nuclei" / "templates"
        try:
            self.templates_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Templates directory initialized: {self.templates_dir}")
        except Exception as e:
            logger.error(f"Failed to create templates directory: {e}")
            raise

    @kernel_function(description="Run a nuclei scan on a target")
    def nuclei_scan(
        self,
        target: Annotated[str, "The target URL or IP to scan"],
        severity: Annotated[str, "Severity level (low, medium, high, critical)"] = "medium",
        tags: Annotated[str, "Comma-separated list of tags to include"] = "",
        exclude_tags: Annotated[str, "Comma-separated list of tags to exclude"] = ""
    ) -> str:
        """
        Run a nuclei scan on a target.
        
        Args:
            target: The target URL or IP to scan
            severity: Minimum severity level to report
            tags: Comma-separated list of tags to include
            exclude_tags: Comma-separated list of tags to exclude
            
        Returns:
            Formatted scan results
        """
        log_separator(logger, f"Starting nuclei scan on {target}", logging.INFO)
        logger.debug(f"Scan parameters - Severity: {severity}, Tags: {tags}, Exclude Tags: {exclude_tags}")

        try:
            cmd = [self.nuclei_path, "-u", target, "-json"]
            
            if severity:
                cmd.extend(["-severity", severity])
            if tags:
                cmd.extend(["-tags", tags])
            if exclude_tags:
                cmd.extend(["-exclude-tags", exclude_tags])

            logger.debug(f"Executing command: {' '.join(cmd)}")

            # Run nuclei scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            results = []
            errors = []

            # Process output line by line
            logger.info("Processing scan output...")
            for line in process.stdout:
                try:
                    logger.debug(f"Processing output line: {line.strip()}")
                    result = json.loads(line.strip())
                    results.append(NucleiResult(**result))
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse JSON line: {line.strip()}")
                    errors.append(line.strip())
                except Exception as e:
                    logger.error(f"Error processing result line: {e}")
                    errors.append(str(e))

            # Wait for process to complete
            process.wait()
            logger.debug(f"Process exit code: {process.returncode}")

            # Format results
            if not results:
                logger.info("No vulnerabilities found")
                return "No vulnerabilities found."

            output = ["Scan Results:"]
            for result in results:
                logger.debug(f"Formatting result: {result}")
                output.append(f"\nTemplate: {result.template}")
                output.append(f"Severity: {result.severity}")
                output.append(f"Host: {result.host}")
                output.append(f"Details: {result.matched}")
                if result.curl_command:
                    output.append(f"Curl Command: {result.curl_command}")
                output.append("-" * 40)

            if errors:
                logger.warning("Scan completed with warnings/errors")
                output.append("\nWarnings/Errors:")
                output.extend(errors)

            formatted_output = "\n".join(output)
            logger.info("Scan completed successfully")
            logger.debug(f"Formatted output: {formatted_output}")
            return formatted_output

        except subprocess.CalledProcessError as e:
            error_msg = f"Error running nuclei scan: {e.stderr}"
            logger.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return error_msg

    @kernel_function(description="Upload a custom nuclei template")
    def upload_template(
        self,
        content: Annotated[str, "Template content in YAML format"],
        category: Annotated[str, "Template category for organization"] = "custom"
    ) -> str:
        """
        Upload a custom nuclei template.
        
        Args:
            content: Template content in YAML format
            category: Template category for organization
            
        Returns:
            Success or error message
        """
        log_separator(logger, "Uploading nuclei template", logging.INFO)
        logger.debug(f"Template category: {category}")

        try:
            # Validate YAML format
            logger.info("Validating template YAML format")
            template = yaml.safe_load(content)
            logger.debug(f"Parsed template: {template}")

            if not template.get("id"):
                logger.error("Template validation failed: Missing ID")
                return "Error: Template must have an ID"

            # Create category directory
            category_dir = self.templates_dir / category
            try:
                category_dir.mkdir(exist_ok=True)
                logger.info(f"Created category directory: {category_dir}")
            except Exception as e:
                logger.error(f"Failed to create category directory: {e}")
                raise

            # Save template
            template_path = category_dir / f"{template['id']}.yaml"
            logger.debug(f"Writing template to: {template_path}")
            with open(template_path, "w") as f:
                f.write(content)

            logger.info(f"Template {template['id']} uploaded successfully")
            return f"Template {template['id']} uploaded successfully"

        except yaml.YAMLError as e:
            error_msg = f"Invalid YAML format: {e}"
            logger.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Error uploading template: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return error_msg

    @kernel_function(description="List available nuclei templates")
    def list_templates(
        self,
        category: Annotated[str, "Template category to list"] = ""
    ) -> str:
        """
        List available nuclei templates.
        
        Args:
            category: Template category to list (empty for all)
            
        Returns:
            List of available templates
        """
        log_separator(logger, "Listing nuclei templates", logging.INFO)
        logger.debug(f"Category filter: {category}")

        try:
            templates = []
            search_dir = self.templates_dir / category if category else self.templates_dir
            
            if not search_dir.exists():
                logger.warning(f"Category directory not found: {search_dir}")
                return f"Category {category} not found"

            logger.info(f"Searching for templates in: {search_dir}")
            for template_file in search_dir.rglob("*.yaml"):
                try:
                    logger.debug(f"Processing template file: {template_file}")
                    with open(template_file) as f:
                        template = yaml.safe_load(f)
                        templates.append({
                            "id": template.get("id", "unknown"),
                            "name": template.get("info", {}).get("name", "Unnamed"),
                            "severity": template.get("info", {}).get("severity", "unknown"),
                            "path": str(template_file.relative_to(self.templates_dir))
                        })
                        logger.debug(f"Template loaded: {templates[-1]}")
                except Exception as e:
                    logger.error(f"Error processing template {template_file}: {e}")
                    continue

            if not templates:
                logger.info("No templates found")
                return "No templates found"

            output = ["Available Templates:"]
            for template in templates:
                output.append(f"\nID: {template['id']}")
                output.append(f"Name: {template['name']}")
                output.append(f"Severity: {template['severity']}")
                output.append(f"Path: {template['path']}")
                output.append("-" * 40)

            formatted_output = "\n".join(output)
            logger.info(f"Found {len(templates)} templates")
            logger.debug(f"Formatted output: {formatted_output}")
            return formatted_output

        except Exception as e:
            error_msg = f"Error listing templates: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return error_msg
