#!/usr/bin/env python3
"""
OWASP LLM Security Testing Environment - Quick Start

This script helps you quickly set up and run the OWASP LLM Security testing environment.
"""

import os
import sys
import subprocess
from pathlib import Path
import argparse

def check_prerequisites():
    """Check if required tools are available."""
    print("🔍 Checking prerequisites...")
    
    # Check for Python
    python_found = False
    for python_cmd in ["python", "python3", "python3.11", "python3.10", "python3.9"]:
        if subprocess.run(["which", python_cmd], capture_output=True).returncode == 0:
            print(f"✅ Found Python: {python_cmd}")
            python_found = True
            break
    
    if not python_found:
        print("❌ Python not found. Please install Python 3.8+ and try again.")
        return False
    
    # Check for pip
    pip_found = False
    for pip_cmd in ["pip", "pip3"]:
        if subprocess.run(["which", pip_cmd], capture_output=True).returncode == 0:
            print(f"✅ Found pip: {pip_cmd}")
            pip_found = True
            break
    
    if not pip_found:
        print("❌ pip not found. Please install pip and try again.")
        return False
    
    print("✅ All required tools are available")
    return True

def check_virtual_environment():
    """Check if virtual environment is active or available."""
    venv_path = Path(__file__).parent / "owasp_llm_env"
    
    if not venv_path.exists():
        print("⚠️  Virtual environment not found. Run setup first.")
        return False
    
    # Check if we're in the virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Virtual environment is active")
        return True
    else:
        print("⚠️  Virtual environment exists but not active")
        print("💡 Use 'python start.py' to automatically activate it")
        return True  # Still return True since venv exists

def setup_environment():
    """Set up the testing environment."""
    print("🚀 Setting up OWASP LLM Security Testing Environment...")
    
    try:
        # Run the setup script
        setup_script = Path(__file__).parent / "setup" / "setup_environment.py"
        if setup_script.exists():
            subprocess.run([sys.executable, str(setup_script)], check=True)
            print("✅ Environment setup completed successfully!")
            print("\n🐍 Virtual environment created successfully!")
            print("💡 Use 'python start.py' to automatically activate the environment")
            return True
        else:
            print("❌ Setup script not found")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ Setup failed: {e}")
        return False

def configure_environment():
    """Help user configure the environment."""
    print("\n⚙️  Environment Configuration")
    print("=" * 40)
    
    # Check if .env file exists
    env_file = Path(__file__).parent / ".env"
    env_example = Path(__file__).parent / "env.example"
    
    if not env_file.exists() and env_example.exists():
        print("📝 Creating .env file from template...")
        try:
            import shutil
            shutil.copy(env_example, env_file)
            print("✅ .env file created from template")
            print("⚠️  Please edit .env file with your API keys and settings")
        except Exception as e:
            print(f"❌ Failed to create .env file: {e}")
    elif env_file.exists():
        print("✅ .env file already exists")
    else:
        print("⚠️  No .env template found")

def run_demo():
    """Run a demonstration of the security testing."""
    print("\n🎯 Running Security Demo")
    print("=" * 40)
    
    # Check if we can run the demo
    demo_script = Path(__file__).parent / "exploits" / "llm01-prompt-injection" / "direct_injection.py"
    
    if demo_script.exists():
        print("🔒 Running prompt injection demo...")
        try:
            subprocess.run([sys.executable, str(demo_script)], check=True)
            print("✅ Demo completed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Demo failed: {e}")
            print("💡 Make sure you have configured your API keys in .env file")
    else:
        print("❌ Demo script not found")

def start_vulnerable_app():
    """Start the vulnerable web application for testing."""
    print("\n🌐 Starting Vulnerable Web Application")
    print("=" * 40)
    
    app_script = Path(__file__).parent / "labs" / "vulnerable_llm_app.py"
    
    if app_script.exists():
        print("🔓 Starting vulnerable LLM web application...")
        print("⚠️  This application is intentionally vulnerable for educational purposes")
        print("🌍 Access the application at: http://localhost:5000")
        print("🔧 Admin panel: http://localhost:5000/admin")
        print("🔍 Debug info: http://localhost:5000/debug")
        print("\nPress Ctrl+C to stop the application")
        
        try:
            subprocess.run([sys.executable, str(app_script)])
        except KeyboardInterrupt:
            print("\n✅ Application stopped")
    else:
        print("❌ Vulnerable app script not found")

def run_security_scan():
    """Run the security scanner."""
    print("\n🔍 Running Security Scanner")
    print("=" * 40)
    
    scanner_script = Path(__file__).parent / "tools" / "security_scanner.py"
    
    if scanner_script.exists():
        print("🔒 Running comprehensive security scan...")
        try:
            subprocess.run([sys.executable, str(scanner_script), "--verbose"], check=True)
            print("✅ Security scan completed!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Security scan failed: {e}")
    else:
        print("❌ Security scanner not found")

def show_menu():
    """Show the main menu."""
    print("\n" + "=" * 60)
    print("🔒 OWASP LLM Security Testing Environment")
    print("=" * 60)
    print("Choose an option:")
    print("1. Setup Environment")
    print("2. Configure API Keys")
    print("3. Run Security Demo")
    print("4. Start Vulnerable Web App")
    print("5. Run Security Scanner")
    print("6. Show Documentation")
    print("7. Exit")
    print("=" * 60)

def show_documentation():
    """Show documentation and resources."""
    print("\n📚 Documentation and Resources")
    print("=" * 40)
    
    docs_path = Path(__file__).parent / "docs"
    
    if docs_path.exists():
        print("📖 Available Documentation:")
        for doc_file in docs_path.glob("*.md"):
            print(f"  - {doc_file.name}")
    
    print("\n🌐 Online Resources:")
    print("  - OWASP GenAI Security Project: https://genai.owasp.org/")
    print("  - LLM Top 10 for 2025: https://genai.owasp.org/llm-top-10/")
    print("  - Agentic AI Security Guide: https://genai.owasp.org/agentic-app-security/")
    
    print("\n📁 Local Files:")
    print("  - README.md: Main documentation")
    print("  - docs/OWASP_LLM_TOP_10_GUIDE.md: Comprehensive security guide")
    print("  - exploits/: Vulnerability demonstrations")
    print("  - tools/: Security testing tools")
    print("  - labs/: Educational labs")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="OWASP LLM Security Testing Environment")
    parser.add_argument("--setup", action="store_true", help="Run setup only")
    parser.add_argument("--demo", action="store_true", help="Run demo only")
    parser.add_argument("--app", action="store_true", help="Start vulnerable app only")
    parser.add_argument("--scan", action="store_true", help="Run security scan only")
    parser.add_argument("--docs", action="store_true", help="Show documentation only")
    
    args = parser.parse_args()
    
    if args.setup:
        if check_prerequisites():
            setup_environment()
            configure_environment()
        return
    
    # Check virtual environment for other operations
    if not args.setup:
        check_virtual_environment()
    
    if args.demo:
        run_demo()
        return
    
    if args.app:
        start_vulnerable_app()
        return
    
    if args.scan:
        run_security_scan()
        return
    
    if args.docs:
        show_documentation()
        return
    
    # Interactive mode
    while True:
        show_menu()
        
        try:
            choice = input("Enter your choice (1-7): ").strip()
            
            if choice == "1":
                if check_prerequisites():
                    setup_environment()
                    configure_environment()
            
            elif choice == "2":
                configure_environment()
            
            elif choice == "3":
                run_demo()
            
            elif choice == "4":
                start_vulnerable_app()
            
            elif choice == "5":
                run_security_scan()
            
            elif choice == "6":
                show_documentation()
            
            elif choice == "7":
                print("👋 Goodbye! Stay secure!")
                break
            
            else:
                print("❌ Invalid choice. Please enter a number between 1-7.")
        
        except KeyboardInterrupt:
            print("\n👋 Goodbye! Stay secure!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main() 