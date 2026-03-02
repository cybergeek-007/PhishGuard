#!/usr/bin/env python3
"""
PhishGuard Launcher
===================
Entry point for running the PhishGuard analysis platform.
"""

import os
import sys
import argparse


def check_dependencies():
    """Check if required dependencies are installed"""
    required = [
        'streamlit', 'pandas', 'requests', 'beautifulsoup4',
        'Levenshtein', 'tldextract', 'dns', 'dkim', 'spf'
    ]
    
    missing = []
    for package in required:
        try:
            if package == 'Levenshtein':
                __import__('Levenshtein')
            elif package == 'dns':
                __import__('dns.resolver')
            elif package == 'dkim':
                __import__('dkim')
            elif package == 'spf':
                __import__('spf')
            else:
                __import__(package.replace('-', '_').lower())
        except ImportError:
            missing.append(package)
    
    if missing:
        print("❌ Missing dependencies:")
        for pkg in missing:
            print(f"   - {pkg}")
        print("\n📦 Install with: pip install -r requirements.txt")
        return False
    
    return True


def run_dashboard():
    """Run the Streamlit dashboard"""
    import subprocess
    
    dashboard_path = os.path.join(os.path.dirname(__file__), 'dashboard.py')
    
    print("🚀 Starting PhishGuard Dashboard...")
    print("=" * 50)
    
    try:
        subprocess.run(['streamlit', 'run', dashboard_path], check=True)
    except FileNotFoundError:
        print("❌ Streamlit not found. Install with: pip install streamlit")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Dashboard stopped")


def run_cli_analysis(file_path):
    """Run CLI analysis on an email file"""
    from modules.analyzer_engine import PhishGuardAnalyzer
    from config import API_KEYS, CACHE_CONFIG
    
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    
    print(f"🔍 Analyzing: {file_path}")
    print("=" * 50)
    
    analyzer = PhishGuardAnalyzer(api_keys=API_KEYS, cache_file=CACHE_CONFIG['storage'])
    result = analyzer.analyze_eml_file(file_path)
    
    if result:
        print(analyzer.generate_report(result, format='text'))
    else:
        print("❌ Failed to analyze email")
        sys.exit(1)


def run_tests():
    """Run test analysis on sample files"""
    from modules.analyzer_engine import PhishGuardAnalyzer
    from config import API_KEYS, CACHE_CONFIG
    
    test_dir = os.path.join(os.path.dirname(__file__), 'test_data')
    
    if not os.path.exists(test_dir):
        print("❌ Test data directory not found")
        sys.exit(1)
    
    analyzer = PhishGuardAnalyzer(api_keys=API_KEYS, cache_file=CACHE_CONFIG['storage'])
    
    print("🧪 Running test analysis...")
    print("=" * 70)
    
    for filename in sorted(os.listdir(test_dir)):
        if filename.endswith('.eml'):
            filepath = os.path.join(test_dir, filename)
            print(f"\n📧 Testing: {filename}")
            print("-" * 70)
            
            result = analyzer.analyze_eml_file(filepath)
            
            if result:
                score = result.get('threat_score', 0)
                classification = result.get('classification', 'UNKNOWN')
                
                icon = "🔴" if score >= 71 else "🟠" if score >= 31 else "🟢"
                print(f"Result: {icon} Score {score}/100 - {classification}")
                print(f"Auth: SPF={result['authentication']['spf']['result']}, "
                      f"DKIM={result['authentication']['dkim']['result']}, "
                      f"DMARC={result['authentication']['dmarc'].get('policy', 'none')}")
            else:
                print("❌ Analysis failed")
    
    print("\n" + "=" * 70)
    print("✅ Tests completed")


def main():
    parser = argparse.ArgumentParser(
        description='PhishGuard - Email Security Analysis Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py dashboard          # Launch web dashboard
  python run.py analyze email.eml  # Analyze single email
  python run.py test               # Run tests on sample files
        """
    )
    
    parser.add_argument(
        'command',
        choices=['dashboard', 'analyze', 'test'],
        help='Command to run'
    )
    parser.add_argument(
        'file',
        nargs='?',
        help='Email file to analyze (for analyze command)'
    )
    
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Execute command
    if args.command == 'dashboard':
        run_dashboard()
    elif args.command == 'analyze':
        if not args.file:
            print("❌ Please specify an email file to analyze")
            parser.print_help()
            sys.exit(1)
        run_cli_analysis(args.file)
    elif args.command == 'test':
        run_tests()


if __name__ == '__main__':
    main()
