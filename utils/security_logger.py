#!/usr/bin/env python3
"""
Security Logger Utility

Provides enhanced logging capabilities specifically designed for security testing,
with features for tracking attacks, vulnerabilities, and security events.
"""

import os
import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import sys

class SecurityLogger:
    """
    Enhanced logger for security testing and monitoring.
    
    Provides structured logging with security-specific features including
    attack tracking, vulnerability reporting, and audit trails.
    """
    
    def __init__(self, name: str, log_level: str = "INFO"):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Create logs directory if it doesn't exist
        logs_dir = Path(__file__).parent.parent / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        # Set up handlers
        self._setup_handlers(logs_dir)
        
        # Security event tracking
        self.security_events = []
        self.attack_attempts = 0
        self.vulnerabilities_found = 0
        
    def _setup_handlers(self, logs_dir: Path):
        """Set up logging handlers."""
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        # File handler for general logs
        file_handler = logging.FileHandler(logs_dir / "security.log")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        
        # Security events handler
        security_handler = logging.FileHandler(logs_dir / "security_events.log")
        security_handler.setLevel(logging.INFO)
        security_formatter = logging.Formatter(
            '%(asctime)s [SECURITY] %(name)s: %(message)s'
        )
        security_handler.setFormatter(security_formatter)
        
        # Add handlers
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(security_handler)
        
    def info(self, message: str, **kwargs):
        """Log info message with optional context."""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message with optional context."""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message with optional context."""
        self.logger.error(message, extra=kwargs)
    
    def debug(self, message: str, **kwargs):
        """Log debug message with optional context."""
        self.logger.debug(message, extra=kwargs)
    
    def security_event(self, event_type: str, description: str, severity: str = "MEDIUM", 
                      details: Optional[Dict[str, Any]] = None):
        """
        Log a security event with structured information.
        
        Args:
            event_type: Type of security event (e.g., "ATTACK", "VULNERABILITY", "BREACH")
            description: Human-readable description
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            details: Additional structured details
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "description": description,
            "severity": severity,
            "logger": self.name,
            "details": details or {}
        }
        
        # Log the event
        self.logger.warning(f"SECURITY EVENT: {event_type} - {description}", extra=event)
        
        # Store for reporting
        self.security_events.append(event)
        
        # Update counters
        if event_type == "ATTACK":
            self.attack_attempts += 1
        elif event_type == "VULNERABILITY":
            self.vulnerabilities_found += 1
    
    def attack_detected(self, attack_type: str, target: str, payload: str, 
                       success: bool, details: Optional[Dict] = None):
        """
        Log a detected attack attempt.
        
        Args:
            attack_type: Type of attack (e.g., "PROMPT_INJECTION", "XSS")
            target: Target system or component
            payload: The malicious payload used
            success: Whether the attack was successful
            details: Additional attack details
        """
        severity = "HIGH" if success else "MEDIUM"
        
        self.security_event(
            event_type="ATTACK",
            description=f"{attack_type} attack against {target} - {'SUCCESS' if success else 'BLOCKED'}",
            severity=severity,
            details={
                "attack_type": attack_type,
                "target": target,
                "payload": payload,
                "success": success,
                **details or {}
            }
        )
    
    def vulnerability_found(self, vuln_type: str, component: str, description: str,
                          cve_id: Optional[str] = None, details: Optional[Dict] = None):
        """
        Log a discovered vulnerability.
        
        Args:
            vuln_type: Type of vulnerability
            component: Affected component
            description: Vulnerability description
            cve_id: CVE identifier if available
            details: Additional vulnerability details
        """
        self.security_event(
            event_type="VULNERABILITY",
            description=f"{vuln_type} vulnerability in {component}: {description}",
            severity="HIGH",
            details={
                "vuln_type": vuln_type,
                "component": component,
                "description": description,
                "cve_id": cve_id,
                **details or {}
            }
        )
    
    def security_audit(self, audit_type: str, target: str, findings: Dict[str, Any]):
        """
        Log security audit results.
        
        Args:
            audit_type: Type of audit performed
            target: Target of the audit
            findings: Audit findings and results
        """
        self.security_event(
            event_type="AUDIT",
            description=f"{audit_type} audit of {target} completed",
            severity="INFO",
            details={
                "audit_type": audit_type,
                "target": target,
                "findings": findings
            }
        )
    
    def performance_metric(self, metric_name: str, value: float, unit: str = "", 
                         context: Optional[Dict] = None):
        """
        Log performance metrics for security testing.
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Unit of measurement
            context: Additional context
        """
        self.info(f"PERFORMANCE: {metric_name} = {value}{unit}", 
                 extra={"metric": metric_name, "value": value, "unit": unit, **context or {}})
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get a summary of security events and metrics."""
        return {
            "total_events": len(self.security_events),
            "attack_attempts": self.attack_attempts,
            "vulnerabilities_found": self.vulnerabilities_found,
            "events_by_type": self._count_events_by_type(),
            "events_by_severity": self._count_events_by_severity(),
            "recent_events": self.security_events[-10:] if self.security_events else []
        }
    
    def _count_events_by_type(self) -> Dict[str, int]:
        """Count events by type."""
        counts = {}
        for event in self.security_events:
            event_type = event["event_type"]
            counts[event_type] = counts.get(event_type, 0) + 1
        return counts
    
    def _count_events_by_severity(self) -> Dict[str, int]:
        """Count events by severity."""
        counts = {}
        for event in self.security_events:
            severity = event["severity"]
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def export_events(self, filename: str = None) -> str:
        """
        Export security events to a JSON file.
        
        Args:
            filename: Optional filename, defaults to timestamped name
            
        Returns:
            Path to the exported file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_events_{timestamp}.json"
        
        export_path = Path(__file__).parent.parent / "logs" / filename
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "logger_name": self.name,
            "summary": self.get_security_summary(),
            "events": self.security_events
        }
        
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.info(f"Security events exported to {export_path}")
        return str(export_path)
    
    def clear_events(self):
        """Clear stored security events."""
        self.security_events.clear()
        self.attack_attempts = 0
        self.vulnerabilities_found = 0
        self.info("Security events cleared") 