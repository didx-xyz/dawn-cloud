package xyz.didx
import munit.CatsEffectSuite

import java.util.*

import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.*
import cats.effect.IO
import io.circe.parser.*
import cats.data.EitherT
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.JwkBuilder
import io.jsonwebtoken.security.EcPrivateJwk
import Crypto.*
import org.bouncycastle.jce.interfaces.ECPublicKey
import io.circe.DecodingFailure
import crypto.KeyType.*
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Object
import java.io.ByteArrayOutputStream
import org.bouncycastle.asn1.ASN1OutputStream
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.security.*
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.ECParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class CryptoSpec extends CatsEffectSuite {

  test("keys") {

    val jwk                           = crypto.KeyType.createEd25519JWKKey
    val jcaKeyPair                    = crypto.KeyType.createEd25519JCAKey
    println(jwk.toString())
    println(s"JWK: ${jwk.toPublicJWK}")
    println(s"JCA1: ${jcaKeyPair.toPublicJWK}")
    jcaKeyPair match
      case Ed25519JCAKey(keyPair) =>
        keyPair.getPublic match
          case p: Ed25519PublicKeyParameters =>
            val d   = Base64URL.encode(p.getEncoded())
            val jwk = new OctetKeyPair.Builder(Curve.Ed25519, d)
              .issueTime(new Date())
              .keyUse(KeyUse.SIGNATURE)
              .build()
            println(s"JCA2: ${jwk.toPublicJWK}")
      case _                      => println("Unsupported key type")
    val keyPairGenerator              = KeyPairGenerator.getInstance("ECDSA", "BC")
    val eccParameters: X9ECParameters = CustomNamedCurves.getByName("secp256k1")
    val eccSpec: ECParameterSpec      = EC5Util.convertToSpec(eccParameters)
    keyPairGenerator.initialize(eccSpec)
    val kp                            = keyPairGenerator.generateKeyPair()
    val jwk2                          = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(kp.getPublic.getEncoded()))
      .issueTime(new Date())
      .keyUse(KeyUse.SIGNATURE)
      .build()
    println(s"JCA3: ${jwk2.toPublicJWK}")

  }
}
