id: file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala:[6568..6571) in Input.VirtualFile("file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala", "
package xyz.didx.crypto

import com.nimbusds.jose.jwk.gen.*
import com.nimbusds.jose.jwk.*

import java.security.spec.ECPoint
import java.security.interfaces.*
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.util.Base64
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.http4s.CacheDirective.public
import org.bouncycastle.crypto.params.*




enum KeyType:
  case Ed25519Key(key: OctetKeyPair) 
  case X25519Key(key: OctetKeyPair)
  case RSAKey(size: Int, key: com.nimbusds.jose.jwk.RSAKey)
  case EllipticCurveKey(curveName: String, key: com.nimbusds.jose.jwk.ECKey)

  def toPublicJWK(): JWK = this match {
    case Ed25519Key(key) => key.toPublicJWK()
    case X25519Key(key) => key.toPublicJWK()
    case RSAKey(size, key) => key.toPublicJWK()
    case EllipticCurveKey(curveName, key) => key.toPublicJWK()
  }

  def toJavaPublicKey: java.security.PublicKey = this match {
    case Ed25519Key(key) => {
      val publicKeyParams = new Ed25519PublicKeyParameters(key.getDecodedX())
      val subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParams)

      // Get the elliptic curve parameter specification for the secp160r2 curve
      val keyFactory = KeyFactory.getInstance("Ed25519", "BC")
      val publicKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded())
      keyFactory.generatePublic(publicKeySpec)

    }
    case X25519Key(key) => {
      val publicKeyParams = new X25519PublicKeyParameters(key.getDecodedX())
      val subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKeyParams)

      // Get the elliptic curve parameter specification for the secp160r2 curve
      val keyFactory = KeyFactory.getInstance("X25519", "BC")
      val publicKeySpec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded())
      keyFactory.generatePublic(publicKeySpec)

    } 
    case RSAKey(size, key) => key.toPublicJWK().toRSAPublicKey()
    case EllipticCurveKey(curveName, key) => key.toECPublicKey()
  }

  def toJavaPrivateKey: java.security.PrivateKey = this match {
    case Ed25519Key(key) => {
      val privateKeyParams = new Ed25519PrivateKeyParameters(key.getDecodedD())
      val subjectPrivateKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(privateKeyParams)

      // Get the elliptic curve parameter specification for the secp160r2 curve
      val keyFactory = KeyFactory.getInstance("Ed25519", "BC")
      val privateKeySpec = new X509EncodedKeySpec(subjectPrivateKeyInfo.getEncoded())
      keyFactory.generatePrivate(privateKeySpec)

    }
    case X25519Key(key) => {
      val privateKeyParams = new X25519PrivateKeyParameters(key.getDecodedD())
      val subjectPrivateKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(privateKeyParams)

      // Get the elliptic curve parameter specification for the secp160r2 curve
      val keyFactory = KeyFactory.getInstance("X25519", "BC")
      val privateKeySpec = new X509EncodedKeySpec(subjectPrivateKeyInfo.getEncoded())
      keyFactory.generatePrivate(privateKeySpec)

    } 
    case RSAKey(size, key) => key.toRSAPrivateKey()
    case EllipticCurveKey(curveName, key) => key.toECPrivateKey()
  }

 

object KeyType {
  Security.addProvider(new BouncyCastleProvider())

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
  def createRSAKey(length:Int): KeyType = {
    val keyGen = new RSAKeyGenerator(length)
    val keyPair = keyGen.generate()
    KeyType.RSAKey(length,keyPair.toRSAKey())
  }

  // Elliptic Curve Key (EC)
  def createEllipticCurveKey(curve: Curve): KeyType = {
    val keyGen = new ECKeyGenerator(curve)
    val keyPair = keyGen.generate()
    val publicKey = keyPair.toECKey()
    //val privateKey = keyPair.toECPKey()
    KeyType.EllipticCurveKey(curve.toString, publicKey)//, Some(privateKey))

   
  }

  def fromPublicKey(publicKey: String): KeyType = {
       publicKey match
         case s: String if s.startsWith("MCowBQYDK2VwAyEA") => 
           val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
           val keyGen = new OctetKeyPairGenerator(Curve.Ed25519)
           val keyPair = keyGen.generate()
           KeyType.X25519Key(keyPair.toOctetKeyPair())
         case s: String if s.startsWith("MCowBQYDK2VuAyEA") => 
           val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
           val keyGen = new OctetKeyPairGenerator(Curve.X25519)
           val keyPair = keyGen.generate()
           KeyType.X25519Key(keyPair.toOctetKeyPair())
         case s: String if s.startsWith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA") =>
            val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
            val keyGen = new RSAKeyGenerator(2048)
            val keyPair = keyGen.generate()
            KeyType.RSAKey(2048,keyPair.toRSAKey())
         case s: String if s.startsWith("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA") =>
            val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
            val keyGen = new RSAKeyGenerator(4096)
            val keyPair = keyGen.generate()
            KeyType.RSAKey(4096,keyPair.toRSAKey())
         case s: String if s.startsWith("MHYwEAYHKoZIzj0CAQYFK4EEA") =>
            val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
            val keyGen = new ECKeyGenerator(Curve.P_384)
            val keyPair = keyGen.generate()
            val pKey = keyPair.toECKey()
            KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
         case s: String if s.startsWith("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ") =>
            val decodedKeyBytes = java.util.Base64.getUrlDecoder.decode(publicKey)
            val keyGen = new ECKeyGenerator(Curve.P_521)
            val keyPair = keyGen.generate()
            val pKey = keyPair.toECKey()
            KeyType.EllipticCurveKey(pKey.getCurve().toString(), pKey)
         case _ => throw new Exception("Unsupported key type")


   }
   def 
 


  def main(args: Array[String]): Unit = {
    val ed25519KeyPair = createEd25519Key()
    val x25519KeyPair = createX25519Key()
    val rsaKeyPair2048 = createRSAKey(2048)
    val rsaKeyPair4096 = createRSAKey(4096)
    val ellipticCurveKey = createEllipticCurveKey(Curve.P_384)
    val ellipticCurveKey2 = createEllipticCurveKey(Curve.P_521)
   // val ellipticCurveKey3 = createEllipticCurveKey(Curve.SECP256K1)
    val pubKey1 = Base64.getUrlEncoder.encodeToString(ed25519KeyPair.toJavaPublicKey.getEncoded())
    val pubKey2 = Base64.getUrlEncoder.encodeToString(x25519KeyPair.toJavaPublicKey.getEncoded())
    val pubKey3 = Base64.getUrlEncoder.encodeToString(rsaKeyPair2048.toJavaPublicKey.getEncoded())
    val pubKey4 = Base64.getUrlEncoder.encodeToString(rsaKeyPair4096.toJavaPublicKey.getEncoded())
    val pubKey5 = Base64.getUrlEncoder.encodeToString(ellipticCurveKey.toJavaPublicKey.getEncoded())
    val pubKey6 = Base64.getUrlEncoder.encodeToString(ellipticCurveKey2.toJavaPublicKey.getEncoded())
   // val pubKey7 = Base64.getUrlEncoder.encodeToString(ellipticCurveKey3.toJavaPublicKey.getEncoded())





    println(s"\nEd25519 Key Pair: ${ed25519KeyPair}\n ${pubKey1}")
    println(s"\n${fromPublicKey(pubKey1).toPublicJWK()}")
    println(s"X25519 Key Pair: ${x25519KeyPair}\n ${pubKey2}")
    println(s"${fromPublicKey(pubKey2).toPublicJWK()}")
    println(s"RSA Key Pair: ${rsaKeyPair2048}\n ${pubKey3}")
    println(s"${fromPublicKey(pubKey3).toPublicJWK()}")
    println(s"RSA Key Pair: ${rsaKeyPair4096}\n ${pubKey4}")
    println(s"${fromPublicKey(pubKey4).toPublicJWK()}")
    println(s"Elliptic Key Pair: ${ellipticCurveKey}\n ${pubKey5}")
    println(s"${fromPublicKey(pubKey5).toPublicJWK()}")
    println(s"Elliptic Key Pair: ${ellipticCurveKey2}\n ${pubKey6}")
    println(s"${fromPublicKey(pubKey6).toPublicJWK()}")
    

   // println(s"X25519 Key Pair: $x25519KeyPair")
   // println(s"RSA Key Pair: $rsaKeyPair")
   // println(s"Elliptic Key Pair: $ellipticCurveKey")
  }
}")
file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala
file://<WORKSPACE>/src/xyz/didx/crypto/KeyType.scala:164: error: expected identifier; obtained def
  def main(args: Array[String]): Unit = {
  ^
#### Short summary: 

expected identifier; obtained def