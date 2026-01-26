import os
from huggingface_hub import HfApi

HF_TOKEN = os.environ.get('HF_TOKEN')
HF_REPO = os.environ.get('HF_REPO')

if not HF_TOKEN or not HF_REPO:
    print('HF_TOKEN or HF_REPO not configured. Exiting.')
    raise SystemExit(1)

api = HfApi()

def upload_file(local_path, path_in_repo=None):
    path_in_repo = path_in_repo or os.path.basename(local_path)
    print(f'Uploading {local_path} to {HF_REPO}/{path_in_repo}...')
    res = api.upload_file(
        path_or_fileobj=local_path,
        path_in_repo=path_in_repo,
        repo_id=HF_REPO,
        repo_type='dataset',
        token=HF_TOKEN
    )
    print('Upload response:', res)

if __name__ == '__main__':
    # find latest dataset
    ds_dir = os.path.join(os.path.dirname(__file__), '..', 'datasets')
    latest_meta = os.path.join(ds_dir, 'latest.json')
    if not os.path.exists(latest_meta):
        print('No latest.json found, nothing to upload.')
        raise SystemExit(2)
    import json
    meta = json.load(open(latest_meta, 'r'))
    file_name = meta.get('file')
    if not file_name:
        print('latest.json missing file entry')
        raise SystemExit(3)
    local_file = os.path.join(ds_dir, file_name)
    if not os.path.exists(local_file):
        print('Dataset file not found:', local_file)
        raise SystemExit(4)
    upload_file(local_file, path_in_repo=f'datasets/{file_name}')
