#!/bin/bash
# Quick run script for NIDS

case "$1" in
    monitor)
        echo "Starting NIDS monitor..."
        sudo python src/main_headless_fixed.py --cooldown 0
        ;;
    analyze)
        echo "Analyzing PCAP: $2"
        python src/main_headless_fixed.py --pcap "data/attacks/$2"
        ;;
    attack)
        echo "Generating attack: $2"
        python scripts/attack_generator.py --attack "$2"
        ;;
    test)
        echo "Running tests..."
        python tests/test_final.py
        ;;
    *)
        echo "Usage: ./run.sh [monitor|analyze|attack|test]"
        echo "  monitor              - Start live monitoring"
        echo "  analyze FILE.pcap    - Analyze PCAP file"
        echo "  attack TYPE          - Generate attack (sql_injection, xss, etc)"
        echo "  test                 - Run test suite"
        ;;
esac
