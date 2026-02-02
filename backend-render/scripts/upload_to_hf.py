import os
import json
from datetime import datetime, timezone

from huggingface_hub import HfApi


HF_TOKEN = os.environ.get("HF_TOKEN")
HF_REPO = os.environ.get("HF_REPO")
HF_PRIVATE = os.environ.get("HF_PRIVATE", "").strip().lower() in {"1", "true", "yes"}

if not HF_TOKEN or not HF_REPO:
    print("HF_TOKEN or HF_REPO not configured. Exiting.")
    raise SystemExit(1)

api = HfApi()


def ensure_repo_exists() -> None:
    try:
        api.create_repo(
            repo_id=HF_REPO,
            repo_type="dataset",
            private=HF_PRIVATE,
            exist_ok=True,
            token=HF_TOKEN,
        )
        print(f"Repo ready: https://huggingface.co/datasets/{HF_REPO}")
    except Exception as exc:
        # Non-fatal: repo may already exist or token may not have rights to create it.
        print(f"Repo creation skipped/failed (continuing): {exc}")


def upload_file(local_path: str, path_in_repo: str, commit_message: str) -> None:
    print(f"Uploading {local_path} -> {HF_REPO}:{path_in_repo}")
    res = api.upload_file(
        path_or_fileobj=local_path,
        path_in_repo=path_in_repo,
        repo_id=HF_REPO,
        repo_type="dataset",
        token=HF_TOKEN,
        commit_message=commit_message,
    )
    print("Upload ok:", res)

if __name__ == '__main__':
    ensure_repo_exists()

    # Find latest dataset
    ds_dir = os.path.join(os.path.dirname(__file__), "..", "datasets")
    latest_meta = os.path.join(ds_dir, "latest.json")
    if not os.path.exists(latest_meta):
        print("No latest.json found, nothing to upload.")
        raise SystemExit(2)

    with open(latest_meta, "r", encoding="utf-8") as f:
        meta = json.load(f)
    file_name = meta.get("file")
    if not file_name:
        print("latest.json missing file entry")
        raise SystemExit(3)

    local_file = os.path.join(ds_dir, file_name)
    if not os.path.exists(local_file):
        print("Dataset file not found:", local_file)
        raise SystemExit(4)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    commit_message = f"Update breaches dataset: {file_name} ({ts})"

    # Upload the timestamped snapshot
    upload_file(local_file, path_in_repo=f"datasets/{file_name}", commit_message=commit_message)
    # Upload a stable pointer for consumers
    upload_file(local_file, path_in_repo="datasets/breaches-latest.json", commit_message=commit_message)
    # Upload metadata pointer
    upload_file(latest_meta, path_in_repo="datasets/latest.json", commit_message=commit_message)

    # Upload optional helper files
    new_breaches = os.path.join(ds_dir, "new-breaches.json")
    if os.path.exists(new_breaches):
        upload_file(new_breaches, path_in_repo="datasets/new-breaches.json", commit_message=commit_message)

    print("Done. Browse:")
    print(f"- https://huggingface.co/datasets/{HF_REPO}/tree/main/datasets")
