const bls = require('./bls.js')
const assert = require('assert')

function serializeSubTest(t, cstr) {
  const s = t.toHexStr()
  const t2 = new cstr()
  t2.fromHexStr(s)
  assert.deepEqual(t.serialize(), t2.serialize())
}

/*
  return [min, max)
  assume min < max
*/
function randRange(min, max) {
  return min + Math.floor(Math.random() * (max - min))
}

/*
  select k of [0, n)
  @note not uniformal distribution
*/
function randSelect(k, n) {
  let a = []
  let prev = -1
  for (let i = 0; i < k; i++) {
    const v = randRange(prev + 1, n - (k - i) + 1)
    a.push(v)
    prev = v
  }
  return a
}

describe('bls', () => {
  beforeEach(() => {
    return bls.init();
  });

  describe('serialize', () => {
    let sec;

    beforeEach(() => {
      sec = new bls.SecretKey();
      sec.setByCSPRNG()
    });

    it('should be able to serialize SecretKey', () => {
      serializeSubTest(sec, bls.SecretKey)
    });

    it('should be able to serialize PublicKey', () => {
      const pub = sec.getPublicKey()
      serializeSubTest(pub, bls.PublicKey)
    });

    it('should be able to serialize Signature', () => {
      const msg = 'abc'
      const sig = sec.sign(msg)
      serializeSubTest(sig, bls.Signature)
    });

    it('should be able to serialize Id', () => {
      const id = new bls.Id()
      id.setStr('12345')
      serializeSubTest(id, bls.Id)
    });
  });

  describe('signature', () => {
    it('should be able to verify the signature', () => {
      const sec = new bls.SecretKey()
      sec.setByCSPRNG()
      // sec.dump('secretKey ')
      const pub = sec.getPublicKey()
      // pub.dump('publicKey ')

      const msg = 'doremifa'
      // console.log('msg ' + msg)
      const sig = sec.sign(msg)
      // sig.dump('signature ')
      assert(pub.verify(sig, msg))
    });
  });

  describe('misc', () => {
    it('should be able to get the Id value', () => {
      const idDec = '65535'
      const id = new bls.Id()
      id.setStr(idDec)
      assert(id.getStr(), '65535')
      assert(id.getStr(16), 'ffff')
    });
  });

  describe('share', () => {
    const k = 4
    const n = 10
    const msg = 'this is a pen'
    const msk = []
    const mpk = []
    const idVec = []
    const secVec = []
    const pubVec = []
    const sigVec = []
    let secStr;
    let pubStr;
    let sigStr;
    beforeEach(() => {
      for (let i = 0; i < k; i++) {
        const sk = new bls.SecretKey()
        sk.setByCSPRNG()
        msk.push(sk)

        const pk = sk.getPublicKey()
        mpk.push(pk)
      }
      secStr = msk[0].toHexStr()
      pubStr = mpk[0].toHexStr()
      sigStr = msk[0].sign(msg).toHexStr()
    });

    it('should be able to setup master key' , () => {
      assert(mpk[0].verify(msk[0].sign(msg), msg))
    });

    it('should be able to share and recover', () => {
      /*
        key shareing
      */
      for (let i = 0; i < n; i++) {
        const id = new bls.Id()
    //    blsIdSetInt(id, i + 1)
        id.setByCSPRNG()
        idVec.push(id)
        const sk = new bls.SecretKey()
        sk.share(msk, idVec[i])
        secVec.push(sk)

        const pk = new bls.PublicKey()
        pk.share(mpk, idVec[i])
        pubVec.push(pk)

        const sig = sk.sign(msg)
        sigVec.push(sig)
      }
      /*
        recover
      */
      const idxVec = randSelect(k, n)
      // console.log('idxVec=' + idxVec)
      let subIdVec = []
      let subSecVec = []
      let subPubVec = []
      let subSigVec = []
      for (let i = 0; i < idxVec.length; i++) {
        let idx = idxVec[i]
        subIdVec.push(idVec[idx])
        subSecVec.push(secVec[idx])
        subPubVec.push(pubVec[idx])
        subSigVec.push(sigVec[idx])
      }
      {
        const sec = new bls.SecretKey()
        const pub = new bls.PublicKey()
        const sig = new bls.Signature()

        sec.recover(subSecVec, subIdVec)
        pub.recover(subPubVec, subIdVec)
        sig.recover(subSigVec, subIdVec)
        const s = sec.toHexStr()
        assert(sec.toHexStr(), secStr)
        assert(pub.toHexStr(), pubStr)
        assert(sig.toHexStr(), sigStr)
      }
    });
  });
});
