import os
import yaml
import csv

# Path to the folders containing the CVEs
BASE_DIR = os.path.join(os.path.dirname(__file__), 'statements')

commit_ids = set()
repo_urls = set()

for cve_folder in os.listdir(BASE_DIR):
    folder_path = os.path.join(BASE_DIR, cve_folder)
    yaml_file = os.path.join(folder_path, "statement.yaml")

    if os.path.isfile(yaml_file):
        with open(yaml_file, 'r', encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
                fixes = data.get('fixes', [])

                for fix in fixes:
                    for commit in fix.get('commits', []):
                        commit_id = commit.get('id')
                        repo_url = commit.get('repository')

                        if commit_id:
                            commit_ids.add(commit_id)

                        if repo_url:
                            repo_urls.add(repo_url)

            except yaml.YAMLError as e:
                print(f"Error parsing {yaml_file}: {e}")

# ✅ Save commit IDs to CSV
with open("fixing_commit_ids.csv", "w", newline='', encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Commit ID"])
    for cid in sorted(commit_ids):
        writer.writerow([cid])

# ✅ Save repository URLs to CSV
with open("repository_urls.csv", "w", newline='', encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["Repository URL"])
    for url in sorted(repo_urls):
        writer.writerow([url])

print("✅ CSV files generated:")
print(" - fixing_commit_ids.csv")
print(" - repository_urls.csv")
