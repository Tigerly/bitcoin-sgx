#include "bitcoin_helpers.h"
#include "bitcoin/streams.h"
#include "bitcoin/utilstrencodings.h"
#include "log.h"

#include <algorithm>

using std::vector;

//! generate script lockTime << OP_CLTV << OP_DROP << [userPubkey] << OP_CHECKSIG
//! \param userPubkey
//! \param lockTime
//! \return script
CScript generate_simple_cltv_script(
    const CPubKey &userPubkey, uint32_t lockTime)
{
  return CScript() << lockTime << OP_CHECKLOCKTIMEVERIFY << OP_DROP
                   << ToByteVector(userPubkey) << OP_CHECKSIG;
}

bool DecodeHexTx(
    CMutableTransaction &tx, const std::string &strHexTx, bool fTryNoWitness)
{
  if (!IsHex(strHexTx)) return false;
  vector<unsigned char> txData(ParseHex(strHexTx));
  if (fTryNoWitness) {
    CDataStream ssData(
        txData,
        SER_NETWORK,
        PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    try {
      ssData >> tx;
      if (ssData.eof()) {
        return true;
      }
    } catch (const std::exception &) {
      // Fall through.
    }
  }
  CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
  try {
    ssData >> tx;
  } catch (const std::exception &) {
    return false;
  }
  return true;
}