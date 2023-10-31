id: file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala:[227..231) in Input.VirtualFile("file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala", "
package xyz.didx.crypto

import com.nimbusds.jose.jwk.gen.*
import com.nimbusds.jose.jwk.*
import java.security.spec.ECPoint
import java.security.interfaces.*




enum KeyType:
  case Ed25519Key(key: OctetKeyPair):
    def 
  case X25519Key(key: OctetKeyPair)
  case RSAKey(size: Int, key: com.nimbusds.jose.jwk.RSAKey)
  case EllipticCurveKey(curveName: String, key: com.nimbusds.jose.jwk.ECKey)

object KeyType {

  // Ed25519 Key
  def createEd25519Key(): KeyType = {
    val keyGen = new OctetKeyPairGenerator(Curve.Ed25519)
    val keyPair = keyGen.generate()
    KeyType.Ed25519Key(keyPair.toOctetKeyPair)
  }

  // X25519 Key
  def createX25519Key(): KeyType = {
    val keyGen = new OctetKeyPairGenerator(Curve.X25519)
    val keyPair = keyGen.generate()
    KeyType.X25519Key(keyPair.toOctetKeyPair())
  }

  // RSA Key
  def createRSAKey(): KeyType = {
    val keyGen = new RSAKeyGenerator(4096)
    val keyPair = keyGen.generate()
    KeyType.RSAKey(2048,keyPair.toRSAKey())
  }

  // Elliptic Curve Key (EC)
  def createEllipticCurveKey(curve: Curve): KeyType = {
    val keyGen = new ECKeyGenerator(curve)
    val keyPair = keyGen.generate()
    val publicKey = keyPair.toECKey()
    //val privateKey = keyPair.toECPKey()
    KeyType.EllipticCurveKey(curve.toString, publicKey)//, Some(privateKey))

   
  }



  def main(args: Array[String]): Unit = {
    val ed25519KeyPair = createEd25519Key()
    val x25519KeyPair = createX25519Key()
    val rsaKeyPair = createRSAKey()
    val ellipticCurveKey = createEllipticCurveKey(Curve.P_384)

    println(s"Ed25519 Key Pair: ${ed25519KeyPair}")
    println(s"X25519 Key Pair: $x25519KeyPair")
    println(s"RSA Key Pair: $rsaKeyPair")
    println(s"Elliptic Key Pair: $ellipticCurveKey")
  }
}")
file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala
file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala:15: error: expected identifier; obtained case
  case X25519Key(key: OctetKeyPair)
  ^
#### Short summary: 

expected identifier; obtained case