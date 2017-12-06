const bls = require('./bls.js')

bls.init()
.then(() => {
  console.log('curve order=' + bls.getCurveOrder())
  console.log('all ok')
  benchAll()
})

function bench(label, func, count = 50) {
  const start = Date.now()
  for (let i = 0; i < count; i++) {
    func()
  }
  const end = Date.now()
  const t = (end - start) / count
  console.log(label + ' ' + t + 'ms');
}

function benchBls() {
  const msg = 'hello wasm'
  const sec = new bls.SecretKey()
  sec.setByCSPRNG()
  const pub = sec.getPublicKey()
  const sig = sec.sign(msg)
  bench('time_sign_class', () => sec.sign(msg))
  bench('time_verify_class', () => pub.verify(sig, msg))
}

function benchAll() {
  benchBls()
}