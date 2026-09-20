from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parents[1]))

# Lightweight source checks; full UI tests are intentionally avoided.
def test_source_files_exist():
    base=Path(__file__).parents[1]
    assert (base/"data/policies.json").exists()
    assert (base/"data/tickets.json").exists()
    assert (base/"data/employee_requests.json").exists()
    assert (base/"prompts/system_prompt.txt").exists()

if __name__ == "__main__":
    test_source_files_exist()
    print("Basic checks passed.")
