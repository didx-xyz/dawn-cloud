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
import java.util.UUID
import java.util.Date
import java.security.KeyPairGenerator

enum KeyType:
  case Ed25519JWKKey(keyPair: OctetKeyPair)
  case X25519JWKKey(keyPair: OctetKeyPair)
  case Ed25519JCAKey(keyPair: AsymmetricCipherKeyPair)
  case X25519JCAKey(keyPair: AsymmetricCipherKeyPair)
  case RSAJWKKey(size: Int, key: com.nimbusds.jose.jwk.RSAKey)
  case EllipticCurveJWKKey(curveName: String, key: com.nimbusds.jose.jwk.ECKey)

  def toPublicJWK: Either[Error, JWK] = this.match
    case Ed25519JWKKey(keyPair) => Right(keyPair.toPublicJWK())
    case Ed25519JCAKey(keyPair) => keyPair.getPrivate match {
        case p: Ed25519PrivateKeyParameters =>
          val d = Base64URL.encode(p.getEncoded())
          Right(new OctetKeyPair.Builder(Curve.Ed25519, d)
            .issueTime(new Date())
            .keyUse(KeyUse.SIGNATURE)
            .build().toPublicJWK())
        case _                              => Left(Error("Unsupported key type"))
      }
    case _                      => Left(Error("Unsupported key type"))

object KeyType:
  Security.addProvider(new BouncyCastleProvider())

  // Ed25519 Key
  def createEd25519JCAKey: KeyType =
    val privateKey                            = new Ed25519PrivateKeyParameters(SecureRandom()) // (SecureRandom.getInstanceStrong())
    val publicKey: Ed25519PublicKeyParameters = privateKey.generatePublicKey()
    KeyType.Ed25519JCAKey(AsymmetricCipherKeyPair(publicKey, privateKey))

  // generate a JWK Ed25519 Key
  def createEd25519JWKKey: KeyType =
    val jwk = new OctetKeyPairGenerator(Curve.Ed25519)
      .keyUse(KeyUse.SIGNATURE)        // indicate the intended use of the key (optional)
      .keyID(UUID.randomUUID.toString) // give the key a unique ID (optional)
      .issueTime(new Date)             // issued-at timestamp (optional)
      .generate;
    KeyType.Ed25519JWKKey(jwk)

  def createX25519JWKKey: KeyType =
    val jwk = new OctetKeyPairGenerator(Curve.X25519)
      .keyUse(KeyUse.SIGNATURE)        // indicate the intended use of the key (optional)
      .keyID(UUID.randomUUID.toString) // give the key a unique ID (optional)
      .issueTime(new Date)             // issued-at timestamp (optional)
      .generate;
    KeyType.X25519JWKKey(jwk)

  def createX25519JCAKey: KeyType =
    val privateKey                           = new X25519PrivateKeyParameters(SecureRandom()) // (SecureRandom.getInstanceStrong())
    val publicKey: X25519PublicKeyParameters = privateKey.generatePublicKey()
    KeyType.X25519JCAKey(AsymmetricCipherKeyPair(publicKey, privateKey))

  def createRSAKey(length: Int): KeyType = {
    /*  val keyGen  = new RSAKeyGenerator(length)
     val keyPair = keyGen.generate()
     KeyType.RSAJWKKey(length, keyPair.toRSAKey()) */
    val gen = KeyPairGenerator.getInstance("RSA")
    gen.initialize(length)
    val kp  = gen.generateKeyPair
    val jwk = new com.nimbusds.jose.jwk.RSAKey.Builder(kp.getPublic.asInstanceOf[RSAPublicKey])
      .privateKey(kp.getPrivate())
      .keyUse(KeyUse.SIGNATURE)
      .keyID(UUID.randomUUID().toString())
      .issueTime(new Date())
      .build()
    KeyType.RSAJWKKey(length, jwk)
  }

  // Elliptic Curve Key (EC)
  def createEllipticCurveKey(curve: Curve): KeyType = {
    val keyGen                   = new ECKeyGenerator(curve)
    val keyPair                  = keyGen.generate()
    val publicKey                = keyPair.toECKey()
    val privateKey: ECPrivateKey = keyPair.toECPrivateKey()
    KeyType.EllipticCurveJWKKey(curve.toString, publicKey)
  } // , Some(privateKey))

  def main(args: Array[String]): Unit = {}
