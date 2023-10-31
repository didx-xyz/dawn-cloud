package xyz.didx.crypto

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
import java.security.KeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey
import java.security.SecureRandom
import sttp.model.headers.CacheDirective.Public


enum KeyType:
  case Ed25519Key(keyPair: AsymmetricCipherKeyPair)
  case X25519Key(keyPair: AsymmetricCipherKeyPair)
  case RSAKey(size: Int, key: com.nimbusds.jose.jwk.RSAKey)
  case EllipticCurveKey(curveName: String, key: com.nimbusds.jose.jwk.ECKey)

  def toPublicJWK(): JWK = this.match {
    case X25519Key(keyPair) => keyPair.getPrivate match
      case p:X25519PrivateKeyParameters =>
        val d = Base64URL.encode(p.getEncoded())
        new OctetKeyPair.Builder(Curve.X25519, d).build().toPublicJWK()
      case _                          => throw new Exception("Unsupported key type")
    
      
    case Ed25519Key(keyPair) => keyPair.getPrivate match
      case p:Ed25519PrivateKeyParameters =>
        val d = Base64URL.encode(p.getEncoded())
        new OctetKeyPair.Builder(Curve.Ed25519, d).build().toPublicJWK()
      case _                          => throw new Exception("Unsupported key type")

    
    case RSAKey(size, key)                => key.toPublicJWK()
    case EllipticCurveKey(curveName, key) => key.toPublicJWK()
  }

  def toJCAKeyPair(): KeyPair = this match {
    case Ed25519Key(keypair)                 =>
      val privateKeyParams = keypair.getPrivate.asInstanceOf[Ed25519PrivateKeyParameters]
      val publicKeyParams = keypair.getPublic.asInstanceOf[Ed25519PublicKeyParameters]
      val privateKeySpec =  new EdECPrivateKeySpec(NamedParameterSpec.ED25519,privateKeyParams.getEncoded)
      val x509EncodedPublicKeySpec = new X509EncodedKeySpec(publicKeyParams.getEncoded())
      val x509EncodedPrivateKeySpec = new X509EncodedKeySpec(privateKeyParams.getEncoded())
      val privateKeyEncoded = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams).getEncoded()
      val publicKeyEncoded = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParams).getEncoded()
     // val publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519,new EdECPoint(publicKeyParams.getEncoded()))
      val keyFactory = KeyFactory.getInstance("EdDSA", "BC")
      val privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded))

      //val privateKey = keyFactory.generatePrivate(x509EncodedPrivateKeySpec)
      //val publicKey = keyFactory.generatePublic(x509EncodedPublicKeySpec)
      // Create a new instance of the Ed25519 key pair generator.
      val publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded))
  
      new KeyPair(publicKey, privateKey)
    case X25519Key(key)                   => 
      KeyPair(key.getPublic().asInstanceOf[EdDSAPublicKey], key.getPrivate().asInstanceOf[EdDSAPrivateKey])

    case RSAKey(size, key)                => key.toKeyPair()
    case EllipticCurveKey(curveName, key) => key.toKeyPair()
  }

object KeyType {
  Security.addProvider(new BouncyCastleProvider())

  // Ed25519 Key
  def createEd25519Key(): KeyType = {
   val privateKey = new Ed25519PrivateKeyParameters(SecureRandom.getInstanceStrong())
   val publicKey = privateKey.generatePublicKey()
   KeyType.Ed25519Key(AsymmetricCipherKeyPair(publicKey, privateKey))
  }

  // X25519 Key
  def createX25519Key(): KeyType = {
    val privateKey = new X25519PrivateKeyParameters(SecureRandom.getInstanceStrong())
    val publicKey = privateKey.generatePublicKey()
    KeyType.X25519Key(AsymmetricCipherKeyPair(publicKey, privateKey))
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
    val privateKey: ECPrivateKey = keyPair.toECPrivateKey()
    KeyType.EllipticCurveKey(curve.toString, publicKey) // , Some(privateKey))

  }

  def fromPublicKey(publicKey: String): JWK =
    publicKey match
      case s: String if s.startsWith("MCowBQYDK2VwAyEA")                             =>
        val publicKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey.getBytes())
        val keySpec = new X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance(Curve.Ed25519.getName, "BC")
        val pubKey = keyFactory.generatePublic(keySpec).asInstanceOf[EdDSAPublicKey].getEncoded()
        val keyPair         = new OctetKeyPair.Builder(Curve.Ed25519,Base64URL.encode(Arrays.copyOfRange(pubKey, 12, 44))).build()
      //  val x = keyPair.getX
       // val d = keyPair.getD
       // val xBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(x.toString())
       // val dBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(d.toString())
       // val privateKeyParameters = new Ed25519PrivateKeyParameters(dBytes, 0)
       // val publicKeyParameters = new Ed25519PublicKeyParameters(xBytes, 0)
       // val kp = new AsymmetricCipherKeyPair(publicKeyParameters, privateKeyParameters)
        keyPair.toPublicJWK()
       // KeyType.Ed25519Key(kp)


      case s: String if s.startsWith("MCowBQYDK2VuAyEA")                             =>
        val publicKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey.getBytes())
        val keySpec = new X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance(Curve.X25519.getName, "BC")
        val pubKey = keyFactory.generatePublic(keySpec).asInstanceOf[EdDSAPublicKey].getEncoded()
        val keyPair         = new OctetKeyPair.Builder(Curve.X25519,Base64URL.encode(Arrays.copyOfRange(pubKey, 12, 44))).build()
       /*  val x = keyPair.getX
        val d = keyPair.getD
        val xBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(x.toString())
        val dBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(d.toString())
        val privateKeyParameters = new X25519PrivateKeyParameters(dBytes, 0)
        val publicKeyParameters = new X25519PublicKeyParameters(xBytes, 0)
        val kp = new AsymmetricCipherKeyPair(publicKeyParameters, privateKeyParameters)
        KeyType.X25519Key(kp) */
        keyPair.toPublicJWK()
      case s: String if s.startsWith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA") =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new RSAKeyGenerator(2048)
        val keyPair         = keyGen.generate()
        //KeyType.RSAKey(2048, keyPair.toRSAKey())
        keyPair.toPublicJWK()
      case s: String if s.startsWith("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA") =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new RSAKeyGenerator(4096)
        val keyPair         = keyGen.generate()
        keyPair.toPublicJWK()
        //KeyType.RSAKey(4096, keyPair.toRSAKey())
      case s: String if s.startsWith("MHYwEAYHKoZIzj0CAQYFK4EEA")                    =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new ECKeyGenerator(Curve.P_384)
        val keyPair         = keyGen.generate()
        val pKey            = keyPair.toECKey()
        pKey.toPublicJWK()
       // KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
      case s: String if s.startsWith("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ")          =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
        val keyGen          = new ECKeyGenerator(Curve.P_521)
        val keyPair         = keyGen.generate()
        val pKey            = keyPair.toECKey()
        //KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
        keyPair.toPublicJWK()
      case _                                                                         => throw new Exception("Unsupported key type")

  def fromPrivateKey(privateKey: String): KeyType =
    privateKey match
      case s: String if s.startsWith("MC4CAQAwBQYDK2VwBCIEI")               =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new OctetKeyPairGenerator(Curve.Ed25519)
        val keyPair         = keyGen.generate()
        val x = keyPair.getX
        val d = keyPair.getD
        val xBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(x.toString())
        val dBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(d.toString())
        val privateKeyParameters = new X25519PrivateKeyParameters(dBytes, 0)
        val publicKeyParameters = new X25519PublicKeyParameters(xBytes, 0)
        val kp = new AsymmetricCipherKeyPair(publicKeyParameters, privateKeyParameters)
        KeyType.X25519Key(kp)

      case s: String if s.startsWith("MC4CAQAwBQYDK2VuBCIEI")               =>
        val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(privateKey)
        val keyGen          = new OctetKeyPairGenerator(Curve.X25519)
        val keyPair         = keyGen.generate()
        val x = keyPair.getX
        val d = keyPair.getD
        val xBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(x.toString())
        val dBytes: Array[Byte] = java.util.Base64.getUrlDecoder.decode(d.toString())
        val privateKeyParameters = new X25519PrivateKeyParameters(dBytes, 0)
        val publicKeyParameters = new X25519PublicKeyParameters(xBytes, 0)
        val kp = new AsymmetricCipherKeyPair(publicKeyParameters, privateKeyParameters)
        KeyType.X25519Key(kp)
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
