// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/face.hpp>

namespace ndn {
namespace ndnd {

class DBEntry
{
public:
  bool v4;
  uint8_t ip[16];
  uint16_t port;
  uint32_t ttl;
  uint64_t tp;
  Name prefix;
  int faceId;
};

class NDServer
{
public:
  void
  registerPrefix(const Name& prefix);

  void
  run();

private:
  // if subscribe interest, return 0; if arrival interest, return 1
  int
  parseInterest(const Interest& request, DBEntry& entry);

  void
  subscribeBack(const std::string& url, DBEntry& entry);

  void
  onSubData(const Data& data, DBEntry& entry);

  void
  addRoute(const std::string& url, DBEntry& entry);

  void
  onInterest(const Interest& request);
  void
  onData(const Data& data, DBEntry& entry);
  void 
  onNack(const Interest& interest, const lp::Nack& nack);

private:
  Name m_prefix;
  Face m_face;
  KeyChain m_keyChain;
  std::list<DBEntry> m_db;
};

} // namespace ndnd
} // namespace ndn
