"""
Scanning plugin for security testing using nmap.
"""
from typing import Optional, Dict, Any, List, Annotated
import xml.etree.ElementTree as ET
import semantic_kernel as sk
from semantic_kernel.functions.kernel_function_decorator import kernel_function
from pydantic import BaseModel, Field
import nmap
import logging
from herbie.utils.logging_config import setup_logging, log_separator

# Get logger
logger = logging.getLogger('herbie.scanning')

class NmapScanResult(BaseModel):
    """Model for nmap scan results."""
    host: str
    ports: List[Dict[str, Any]] = Field(default_factory=list)
    os: Optional[str] = None
    status: str
    hostname: Optional[str] = None

class ScanningPlugin:
    """Plugin for security scanning operations."""

    def __init__(self):
        """Initialize the scanning plugin."""
        logger.info("Initializing ScanningPlugin")
        try:
            self.nmap = nmap.PortScanner()
            logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize nmap scanner: {e}")
            raise

    @kernel_function(description="Perform a basic nmap scan of a target")
    def nmap_scan(
        self,
        target: Annotated[str, "Target host or IP address"],
        ports: Annotated[str, "Port range to scan"] = "1-1000",
        arguments: Annotated[str, "Additional nmap arguments"] = "-sT -sV"
    ) -> str:
        """
        Perform a basic nmap scan of a target.
        
        Args:
            target: Target host or IP address
            ports: Port range to scan (default: 1-1000)
            arguments: Additional nmap arguments (default: -sT -sV for TCP connect scan with version detection)
            
        Returns:
            Formatted scan results
        """
        log_separator(logger, f"Starting nmap scan on {target}", logging.INFO)
        logger.debug(f"Scan parameters - Ports: {ports}, Arguments: {arguments}")

        try:
            # Ensure arguments are strings
            target_str = str(target)
            ports_str = str(ports)
            arguments_str = str(arguments)

            logger.info(f"Executing nmap scan on {target_str}")
            scan_result = self.nmap.scan(target_str, ports_str, arguments_str)
            logger.debug(f"Raw scan result: {scan_result}")
            
            results = []
            for host in self.nmap.all_hosts():
                logger.debug(f"Processing host: {host}")
                host_data = NmapScanResult(
                    host=host,
                    status=self.nmap[host].state(),
                    hostname=self.nmap[host].hostname() if hasattr(self.nmap[host], 'hostname') else None
                )
                
                # Get port information
                if 'tcp' in self.nmap[host]:
                    logger.debug(f"Processing TCP ports for {host}")
                    for port, port_info in self.nmap[host]['tcp'].items():
                        host_data.ports.append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        })
                        logger.debug(f"Port {port} info: {port_info}")
                
                results.append(host_data)
            
            # Format results
            output = []
            for result in results:
                output.append(f"\nHost: {result.host}")
                if result.hostname:
                    output.append(f"Hostname: {result.hostname}")
                output.append(f"Status: {result.status}")
                
                if result.ports:
                    output.append("\nOpen Ports:")
                    for port in result.ports:
                        if port['state'] == 'open':
                            service_info = f"{port['service']}"
                            if port['product']:
                                service_info += f" ({port['product']}"
                                if port['version']:
                                    service_info += f" {port['version']}"
                                service_info += ")"
                            output.append(f"  {port['port']}/tcp - {service_info}")
            
            formatted_output = "\n".join(output)
            logger.info("Scan completed successfully")
            logger.debug(f"Formatted output: {formatted_output}")
            return formatted_output
            
        except Exception as e:
            error_msg = f"Error performing nmap scan: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return error_msg

    @kernel_function(description="Perform a basic TCP connect scan")
    def nmap_tcp_scan(
        self,
        target: Annotated[str, "Target host or IP address"],
        ports: Annotated[str, "Port range to scan"] = "1-1000"
    ) -> str:
        """
        Perform a basic TCP connect scan (does not require root).
        
        Args:
            target: Target host or IP address
            ports: Port range to scan (default: 1-1000)
            
        Returns:
            Formatted scan results
        """
        log_separator(logger, f"Starting TCP scan on {target}", logging.INFO)
        logger.debug(f"Scan parameters - Ports: {ports}")
        return self.nmap_scan(str(target), str(ports), "-sT -sV")
