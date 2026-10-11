"""Read DNF's default configuration model without loading repository metadata."""
import json
import dnf

with dnf.Base() as base:
    base.conf.read()
    base.conf.cacheonly = True
    base.read_all_repos()
    print(json.dumps({
        "main": {key: bool(getattr(base.conf, key)) for key in
                 ("gpgcheck", "repo_gpgcheck", "localpkg_gpgcheck")},
        "reposdir": list(base.conf.reposdir),
        "repos": {repo.id: {"gpgcheck": bool(repo.gpgcheck),
                            "repo_gpgcheck": bool(repo.repo_gpgcheck)}
                  for repo in base.repos.all()},
    }, sort_keys=True))
