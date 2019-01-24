#include "bitcoin/crypto/sha256.h"
#include "log.h"

#include "amount.h"
#include "bitcoin/base58.h"
#include "bitcoin/hash.h"
#include "bitcoin/key.h"
#include "bitcoin/keystore.h"
#include "bitcoin/policy/policy.h"
#include "bitcoin/primitives/transaction.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script/script.h"
#include "bitcoin/script/sign.h"
#include "bitcoin/streams.h"
#include "bitcoin/utilstrencodings.h"
#include "bitcoin_helpers.h"

#include <string>
#include <utility>

using namespace std;

CTransaction redeem_p2sh_utxo(
    const OutPoint &outpoint,
    CAmount fee,
    uint32_t nLockTime,
    const CKeyStore &keyStore,
    const CKeyID privateKeyId,
    const CBitcoinAddress &address) noexcept(false)
{
  const CTxOut &prevOutput = outpoint.GetTxOut();
  const CScript &scriptPubKey = prevOutput.scriptPubKey;

  // extract script id from the scriptPubKey
  CScriptID script;
  CTxDestination dest;
  if (!ExtractDestination(prevOutput.scriptPubKey, dest)) {
    throw runtime_error("non-standard");
  }

  try {
    script = dest.get<CScriptID>();
  } catch (const mapbox::util::bad_variant_access &e) {
    LL_CRITICAL("no redeemscript found in keystore");
    throw invalid_argument("not p2sh");
  }

  CScript redeemScript;
  if (!keyStore.GetCScript(script, redeemScript)) {
    throw invalid_argument("no usable redeemScript in keystore");
  }

  CMutableTransaction unsignedTx;

  // add the utxo as input
  unsignedTx.vin.emplace_back(outpoint.ToCOutPoint(), CScript(), 0);

  // add the output
  const CAmount amount = prevOutput.nValue - fee;
  auto newOutScriptPubkey = GetScriptForDestination(address.Get());
  unsignedTx.vout.emplace_back(amount, newOutScriptPubkey);

  unsignedTx.nLockTime = nLockTime;

  // initialize secp256k1 context
  auto globalHandle = unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());

  unsigned int nIn = 0;
  MutableTransactionSignatureCreator signer(
      &keyStore, &unsignedTx, nIn, prevOutput.nValue, SIGHASH_ALL);

  // generate scriptSig to spend input.
  std::vector<unsigned char> vchSig;
  // the scriptCode is the actually executed script - either the scriptPubKey
  // for non-segwit, non-P2SH scripts, or the redeemscript in non-segwit P2SH
  // scripts see https://en.bitcoin.it/wiki/OP_CHECKSIG
  if (!signer.CreateSig(vchSig, privateKeyId, redeemScript, SIGVERSION_BASE)) {
    throw invalid_argument("can't sign");
  }

  auto sigScript = CScript()
                   << ToByteVector(vchSig) << ToByteVector(redeemScript);
  // embed the signature into the transaction.
  unsignedTx.vin[0].scriptSig = sigScript;

  // create an immutable transaction and serialize it
  CTransaction t(unsignedTx);

  // verify the script
  ScriptError serror = SCRIPT_ERR_OK;
  if (!VerifyScript(
          t.vin[0].scriptSig,
          scriptPubKey,
          nullptr,
          STANDARD_SCRIPT_VERIFY_FLAGS,
          TransactionSignatureChecker(&t, 0, amount),
          &serror)) {
    throw runtime_error("Signing failed: " + string(ScriptErrorString(serror)));
  } else {
    LL_NOTICE("success.");
  }

  return t;
}

bool test_simple_cltv_redeem()
{
  const string sgxPrivKey =
      "cURgah32X7tNqK9NCkpXVVd4bbocWm3UjgwyAGpdVfxicAZynLs5";
  const uint32_t cltvTimeout = 1547863557;
  const int nIn = 1;
  const string rawPrevTxP2SH =
      "0200000001ed25830ab4b42a747687308d581401b0c2daa1380acc76f8c0ec03877443ac"
      "ca0000000048473044022030f7f476e0331e98b5b44ccdbb6846a64dc8f07ae1210f6e52"
      "be4164fb6490f90220031fcaed63aaf14ee9fe55fb54909aa9767c889ae809df5d5e5ac7"
      "6fac3a593401feffffff0264196bee0000000017a914118dce868159ca1bb0e93d0140d1"
      "9403d7d0af5e8700ca9a3b0000000017a914f62f0c57f7a06341c87d7fa3bc7990c25203"
      "932e8775000000";

  SelectParams(CBaseChainParams::REGTEST);
  ECC_Start();

  try {
    CBitcoinSecret secret;
    if (!secret.SetString(sgxPrivKey)) {
      throw runtime_error("cannot parse private key");
    }
    CKey sgxKey = secret.GetKey();
    auto sgxPubkey = sgxKey.GetPubKey();

    CMutableTransaction _prevTx;
    DecodeHexTx(_prevTx, rawPrevTxP2SH, false);
    CTransaction prevTx(_prevTx);

    CBitcoinAddress toAddress;
    toAddress.Set(sgxKey.GetPubKey().GetID());

    auto redeemScript = generate_simple_cltv_script(sgxPubkey, cltvTimeout);

    CBasicKeyStore keyStore;
    keyStore.AddCScript(redeemScript);
    keyStore.AddKey(sgxKey);

    CTransaction t = redeem_p2sh_utxo(
        OutPoint(prevTx, nIn),
        static_cast<CAmount>(1980),
        cltvTimeout,
        keyStore,
        sgxKey.GetPubKey().GetID(),
        CBitcoinAddress(sgxPubkey.GetID()));

    // dump the hex
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << t;

    LL_NOTICE("Final raw tx: %s", HexStr(ssTx).c_str());
    LL_NOTICE("Interpreted as: %s", t.ToString().c_str());
  } catch (const std::exception &e) {
    LL_CRITICAL("error happened: %s", e.what());
    return -1;
  } catch (...) {
    LL_CRITICAL("unknown error happened");
    return -1;
  }
  ECC_Stop();

  return true;
}
