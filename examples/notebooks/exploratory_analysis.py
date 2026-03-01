import json
from pipelines import network_forensics_pipeline
from pipelines import osint_vendor_mapping_pipeline
from pipelines import reporting_pipeline

# 1. Setup paths
network_input = "../synthetic_network_capture_description.md"
osint_input = "../synthetic_osint_dataset.json"

network_output = "/tmp/demo_network_report.json"
osint_output = "/tmp/demo_osint_graph.json"
final_output_dir = "/tmp/demo_reports"

# 2. Run Network Pipeline
print("Running Network Pipeline...")
network_forensics_pipeline.run_pipeline(network_input, network_output)
with open(network_output, 'r') as f:
    print(f"Network Findings: {json.dumps(json.load(f), indent=2)}\n")

# 3. Run OSINT Pipeline
print("Running OSINT Pipeline...")
osint_vendor_mapping_pipeline.run_pipeline(osint_input, osint_output)
with open(osint_output, 'r') as f:
    print(f"OSINT Graph Status: {json.load(f).get('status')}\n")

# 4. Generate Final Brief
print("Generating Final Briefs...")
reporting_pipeline.run_pipeline(network_output, osint_output, final_output_dir)

print(f"Done! Check {final_output_dir} for outputs.")
