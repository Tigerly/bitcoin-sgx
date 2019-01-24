#ifndef BITCOIN_HELPERS_H
#define BITCOIN_HELPERS_H

#include <bitcoin/primitives/transaction.h>
#include <vector>
#include "bitcoin/base58.h"
#include "bitcoin/key.h"
#include "bitcoin/script/script.h"

CScript generate_simple_cltv_script(const CPubKey &pubkey, uint32_t lockTime);
bool DecodeHexTx(
    CMutableTransaction &tx, const std::string &strHexTx, bool fTryNoWitness);

class OutPoint
{
 private:
  CTransactionRef tx;
  uint32_t nOut;

 public:
  OutPoint(CTransaction &tx, uint32_t nOut)
      : tx(MakeTransactionRef(tx)), nOut(nOut)
  {
  }
  const CTxOut &GetTxOut() const { return tx.get()->vout.at(nOut); }
  const uint256 &GetTxHash() const { return tx.get()->GetHash(); }
  uint32_t GetNOut() const { return nOut; }
  const COutPoint ToCOutPoint() const { return COutPoint(GetTxHash(), nOut); }
};

#include <stdio.h>

#define MUST_TRUE(c)                  \
  do {                                \
    if (!(c)) {                       \
      char buf[BUFSIZ] = {'\0'};      \
      snprintf(                       \
          buf,                        \
          sizeof buf,                 \
          "assert failed at %s:%d",   \
          strrchr(__FILE__, '/') + 1, \
          __LINE__);                  \
      throw std::runtime_error(buf);  \
    }                                 \
  } while (false)

#endif  // TESSERACT_BITCOIN_HELPERS_H
