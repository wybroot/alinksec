// Test-only libapt 2.8.3 source-list parser oracle. No acquire, cache generation,
// external commands, key parsing, hooks or network. argv root redirects only the
// disposable fixture. Production never links or invokes this executable.
#include <apt-pkg/configuration.h>
#include <apt-pkg/debmetaindex.h>
#include <apt-pkg/error.h>
#include <apt-pkg/init.h>
#include <apt-pkg/sourcelist.h>
#include <iostream>
#include <string>
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  std::string root = argv[1], binary = argv[2];
  if (binary != "apt" && binary != "apt-get") return 2;
  _config->Set("Dir::Etc", root + "/etc/apt");
  _config->Set("Dir::State", root + "/state");
  _config->Set("APT::Architecture", "amd64");
  if (!pkgInitConfig(*_config)) { _error->DumpErrors(); return 1; }
  // Use the same native MoveSubTree operation as private-cmndline.cc.
  _config->MoveSubTree(("Binary::" + binary).c_str(), nullptr);
  pkgSourceList sources;
  if (!sources.ReadMainList()) { _error->DumpErrors(); return 1; }
  for (auto const *index : sources) {
    auto *deb = dynamic_cast<debReleaseIndex *>(const_cast<metaIndex *>(index));
    if (deb == nullptr) return 2;
    auto options = deb->GetReleaseOptions();
    std::string trusted = index->GetTrusted() == metaIndex::TRI_YES ? "true" :
                          index->GetTrusted() == metaIndex::TRI_NO ? "false" : "unset";
    std::cout << index->GetURI() << '\t' << index->GetDist() << '\t' << trusted << '\t' << index->GetSignedBy();
    for (auto key : {"ALLOW_INSECURE", "ALLOW_WEAK", "ALLOW_DOWNGRADE_TO_INSECURE"})
      std::cout << '\t' << (options.count(key) ? "true" : "false");
    std::cout << '\n';
  }
  if (_error->PendingError()) { _error->DumpErrors(); return 1; }
  return 0;
}
