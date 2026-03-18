#!/bin/bash
# Run this once in Codespaces terminal to finish setup
echo "Setting up project structure..."
[ -d "devcontainer" ] && mv devcontainer .devcontainer && echo "✅ .devcontainer ready"
[ -d "github" ] && mv github .github && echo "✅ .github ready"
pip install -r requirements.txt && echo "✅ Dependencies installed"
echo ""
echo "All done! Run: python scanner.py --mode demo"
