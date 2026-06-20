import sys
sys.path.insert(0, ".")
from dashboard.app import create_app

if __name__ == "__main__":
    app = create_app(data_dir="data/")
    print("\n  EphemeraWatch Dashboard starting...")
    print("  Open http://localhost:8050 in your browser")
    print("  Press Ctrl+C to stop\n")
    app.run(debug=False, port=8050)
