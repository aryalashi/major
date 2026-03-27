#!/bin/bash
echo "========================================="
echo "NIDS DEMO - Generate and Detect Attacks"
echo "========================================="
echo ""

# Generate attacks
echo "1. Generating SQL Injection..."
python scripts/attack_generator.py --attack sql_injection --duration 2 --rate 20

echo ""
echo "2. Generating XSS Attack..."
python scripts/attack_generator.py --attack xss --duration 2 --rate 20

echo ""
echo "3. Generating Command Injection..."
python scripts/attack_generator.py --attack command_injection --duration 2 --rate 20

echo ""
echo "4. Analyzing latest attack..."
LATEST=$(ls -t data/attacks/*.pcap | head -1)
if [ -f "$LATEST" ]; then
    echo "Analyzing: $(basename $LATEST)"
    NIDS_COOLDOWN=0 python src/main_headless_fixed.py --pcap "$LATEST"
fi

echo ""
echo "========================================="
echo "Demo complete! Check data/attacks/ for PCAP files"
echo "========================================="
