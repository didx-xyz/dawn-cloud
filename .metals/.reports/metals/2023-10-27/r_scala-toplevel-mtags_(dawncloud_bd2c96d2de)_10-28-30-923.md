id: file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala:[1300..1303) in Input.VirtualFile("file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala", "package xyz.didx.crypto

import com.nimbusds.jose.jwk.gen.*
import com.nimbusds.jose.jwk.*

import java.security.spec.ECPoint
import java.security.interfaces.*
import java.util.Base64
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.http4s.CacheDirective.public
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.util.*
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory
import java.security.spec.*
import java.security.spec.EdECPrivateKeySpec
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey
import java.util.Arrays

enum KeyType:
  case Ed25519Key(key: OctetKeyPair)
  case X25519Key(key: OctetKeyPair)
  case RSAKey(size: Int, key: com.nimbusds.jose.jwk.RSAKey)
  case EllipticCurveKey(curveName: String, key: com.nimbusds.jose.jwk.ECKey)

  def toPublicJWK(): JWK = this match {
    case Ed25519Key(key)                  => key.toPublicJWK()
    case X25519Key(key)                   => key.toPublicJWK()
    case RSAKey(size, key)                => key.toPublicJWK()
    case EllipticCurveKey(curveName, key) => key.toPublicJWK()
  }

  def

  def toJavaPublicKey: java.security.PublicKey = this match {
    case Ed25519Key(key: OctetKeyPair) =>
      val publicKeyParams = new Ed25519PublicKeyParameters(key.getDecodedX())
      val point           = new EdECPoint(key.getX().decodeToBigInteger().testBit(0), key.getD().decodeToBigInteger())
      val subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParams)
      val publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, point)
      KeyFactory.getInstance("EdDSA").generatePublic(publicKeySpec)

    case X25519Key(key) =>
      val publicKeyParams      = new X25519PublicKeyParameters(key.getDecodedX())
      val subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParams)

      // Get the elliptic curve parameter specification for the secp160r2 curve
      val keyFactory    = KeyFactory.getInstance("X25519", "BC")
      val publicKeySpec = new XECPrivateKeySpec(NamedParameterSpec.X25519, subjectPublicKeyInfo.getEncoded())
      KeyFactory.getInstance("Ed25519", "BC").generatePublic(publicKeySpec)

    case RSAKey(size, key)                => key.toPublicJWK().toRSAPublicKey()
    case EllipticCurveKey(curveName, key) => key.toECPublicKey()
  }

  def toJavaPrivateKey: java.security.PrivateKey = this match {
    case Ed25519Key(key) =>
      val privateKeyParams      = new Ed25519PrivateKeyParameters(key.getDecodedD())
      val subjectPrivateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams)

      // Get the elliptic curve parameter specification for the secp160r2 curve
      val keyFactory     = KeyFactory.getInstance("Ed25519", "BC")
      val privateKeySpec = new EdECPrivateKeySpec(NamedParameterSpec.ED25519, subjectPrivateKeyInfo.getEncoded())
      keyFactory.generatePrivate(privateKeySpec)

    case X25519Key(key) =>
      val privateKeyParams      = new X25519PrivateKeyParameters(key.getDecodedD())
      val subjectPrivateKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(privateKeyParams)

      // Get the elliptic curve parameter specification for the secp160r2 curve
      val keyFactory     = KeyFactory.getInstance("X25519", "BC")
      val privateKeySpec = new X509EncodedKeySpec(subjectPrivateKeyInfo.getEncoded())
      keyFactory.generatePrivate(privateKeySpec)

    case RSAKey(size, key)                => key.toRSAPrivateKey()
    case EllipticCurveKey(curveName, key) => key.toECPrivateKey()
  }

object KeyType {
  Security.addProvider(new BouncyCastleProvider())

  // Ed25519 Key
  def createEd25519Key(): KeyType = {
    val keyGen  = new OctetKeyPairGenerator(Curve.Ed25519)
    val keyPair = keyGen.generate()
    KeyType.Ed25519Key(keyPair.toOctetKeyPair)
  }

  // X25519 Key
  def createX25519Key(): KeyType = {
    val keyGen  = new OctetKeyPairGenerator(Curve.X25519)
    val keyPair = keyGen.generate()
    KeyType.X25519Key(keyPair.toOctetKeyPair())
  }

  // RSA Key
  def createRSAKey(length: Int): KeyType = {
    val keyGen  = new RSAKeyGenerator(length)
    val keyPair = keyGen.generate()
    KeyType.RSAKey(length, keyPair.toRSAKey())
  }

  // Elliptic Curve Key (EC)
  def createEllipticCurveKey(curve: Curve): KeyType = {
    val keyGen    = new ECKeyGenerator(curve)
    val keyPair   = keyGen.generate()
    val publicKey = keyPair.toECKey()
    // val privateKey = keyPair.toECPKey()
    KeyType.EllipticCurveKey(curve.toString, publicKey) // , Some(privateKey))

  }

  def fromPublicKey(publicKey: String): KeyType =
    publicKey match
      case s: String if s.startsWith("MCowBQYDK2VwAyEA")                             =>
        val publicKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey.getBytes())
        val keySpec = new X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance(Curve.Ed25519.getName, "BC")
        val pubKey = keyFactory.generatePublic(keySpec).asInstanceOf[EdDSAPublicKey].getEncoded()
        
        val keyPair         = new OctetKeyPair.Builder(Curve.Ed25519,Base64URL.encode(Arrays.copyOfRange(pubKey, 12, 44))).build()
        KeyType.Ed25519Key(keyPair)
      case s: String if s.startsWith("MCowBQYDK2VuAyEA")                             =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new OctetKeyPairGenerator(Curve.X25519)
        val keyPair         = keyGen.generate()
        KeyType.X25519Key(keyPair.toOctetKeyPair())
      case s: String if s.startsWith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA") =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new RSAKeyGenerator(2048)
        val keyPair         = keyGen.generate()
        KeyType.RSAKey(2048, keyPair.toRSAKey())
      case s: String if s.startsWith("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA") =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new RSAKeyGenerator(4096)
        val keyPair         = keyGen.generate()
        KeyType.RSAKey(4096, keyPair.toRSAKey())
      case s: String if s.startsWith("MHYwEAYHKoZIzj0CAQYFK4EEA")                    =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new ECKeyGenerator(Curve.P_384)
        val keyPair         = keyGen.generate()
        val pKey            = keyPair.toECKey()
        KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
      case s: String if s.startsWith("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ")          =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new ECKeyGenerator(Curve.P_521)
        val keyPair         = keyGen.generate()
        val pKey            = keyPair.toECKey()
        KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
      case _                                                                         => throw new Exception("Unsupported key type")

  def fromPrivateKey(privateKey: String): KeyType =
    privateKey match
      case s: String if s.startsWith("MC4CAQAwBQYDK2VwBCIEI")               =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new OctetKeyPairGenerator(Curve.Ed25519)
        val keyPair         = keyGen.generate()
        KeyType.X25519Key(keyPair.toOctetKeyPair())
      case s: String if s.startsWith("MC4CAQAwBQYDK2VuBCIEI")               =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new OctetKeyPairGenerator(Curve.X25519)
        val keyPair         = keyGen.generate()
        KeyType.X25519Key(keyPair.toOctetKeyPair())
      case s: String if s.startsWith("MIIEpAIBAAKCAQEA")                    =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new RSAKeyGenerator(2048)
        val keyPair         = keyGen.generate()
        KeyType.RSAKey(2048, keyPair.toRSAKey())
      case s: String if s.startsWith("MIIEowIBAAKCAQEA")                    =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new RSAKeyGenerator(4096)
        val keyPair         = keyGen.generate()
        KeyType.RSAKey(4096, keyPair.toRSAKey())
      case s: String if s.startsWith("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ") =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new ECKeyGenerator(Curve.P_384)
        val keyPair         = keyGen.generate()
        val pKey            = keyPair.toECKey()
        KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
      case s: String if s.startsWith("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ") =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new ECKeyGenerator(Curve.P_521)
        val keyPair         = keyGen.generate()
        val pKey            = keyPair.toECKey()
        KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
      case _                                                                => throw new Exception("Unsupported key type")

  def main(args: Array[String]): Unit = {}
}
")
file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala
file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala:39: error: expected identifier; obtained def
  def toJavaPublicKey: java.security.PublicKey = this match {
  ^
#### Short summary: 

expected identifier; obtained def