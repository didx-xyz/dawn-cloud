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

class CryptoSpec extends CatsEffectSuite {

// RSA Key
  test("Generate an RSA KeyPair") {
    val rsaKeyPair2048 = createRSAKey(2048)

  }
  test("Generate an ED25519") {
    val ed25519KeyPair = createEd25519Key()
   

    val pubKey         = ed25519KeyPair.toPublicJWK().toJSONString()
    // val privKey      = Base64.getUrlEncoder.encodeToString(ed25519KeyPair.toJavaPrivateKey.getEncoded())
    val x              = io.circe.parser.parse(ed25519KeyPair.toPublicJWK().toJSONString()).toOption.get.hcursor.downField("x").as[String].toOption.get
    println(s"X: $x")
    // assert(pubKey.contains(x))

    println(s"\nEd25519 Key Pair: $ed25519KeyPair\n $pubKey")
    //println(s"\n${fromPublicKey(pubKey)}")

    val jcaKeyPair = ed25519KeyPair.toJCAKeyPair()
    val jcaPublicKey = Base64.getUrlEncoder.encodeToString(jcaKeyPair.getPublic.getEncoded())
    val jcaPrivateKey = Base64.getUrlEncoder.encodeToString(jcaKeyPair.getPrivate.getEncoded())
    println(s"JCA Key Pair: ${jcaPublicKey} , ${jcaPrivateKey}")
    val pubKey2 = fromPublicKey(jcaPublicKey).toJSONString()
    println(s"PubKey2: $pubKey2") 
    // println(s"\n${fromPrivateKey(privKey)}")

  }
  test("Generate an X25519") {
    val x25519KeyPair = createX25519Key()

  }
  test("Generate an EC P384") {
    val ellipticCurveKey = createEllipticCurveKey(Curve.P_384)
  }
  test("Generate an EC P521") {
    val ellipticCurveKey2 = createEllipticCurveKey(Curve.P_521)

  }

  /*  val rsaKeyPair4096    = createRSAKey(4096)

      // val ellipticCurveKey3 = createEllipticCurveKey(Curve.SECP256K1)
      val pubKey1           = Base64.getUrlEncoder.encodeToString(ed25519KeyPair.toJavaPublicKey.getEncoded())
      val pubKey2           = Base64.getUrlEncoder.encodeToString(x25519KeyPair.toJavaPublicKey.getEncoded())
      val pubKey3           = Base64.getUrlEncoder.encodeToString(rsaKeyPair2048.toJavaPublicKey.getEncoded())
      val pubKey4           = Base64.getUrlEncoder.encodeToString(rsaKeyPair4096.toJavaPublicKey.getEncoded())
      val pubKey5           = Base64.getUrlEncoder.encodeToString(ellipticCurveKey.toJavaPublicKey.getEncoded())
      val pubKey6           = Base64.getUrlEncoder.encodeToString(ellipticCurveKey2.toJavaPublicKey.getEncoded())
      // val pubKey7 = Base64.getUrlEncoder.encodeToString(ellipticCurveKey3.toJavaPublicKey.getEncoded())

      println(s"\nEd25519 Key Pair: $ed25519KeyPair\n $pubKey1")
      println(s"\n${fromPublicKey(pubKey1).toPublicJWK()}")
      println(s"X25519 Key Pair: $x25519KeyPair\n $pubKey2")
      println(s"${fromPublicKey(pubKey2).toPublicJWK()}")
      println(s"RSA Key Pair: $rsaKeyPair2048\n $pubKey3")
      println(s"${fromPublicKey(pubKey3).toPublicJWK()}")
      println(s"RSA Key Pair: $rsaKeyPair4096\n $pubKey4")
      println(s"${fromPublicKey(pubKey4).toPublicJWK()}")
      println(s"Elliptic Key Pair: $ellipticCurveKey\n $pubKey5")
      println(s"${fromPublicKey(pubKey5).toPublicJWK()}")
      println(s"Elliptic Key Pair: $ellipticCurveKey2\n $pubKey6")
      println(s"${fromPublicKey(pubKey6).toPublicJWK()}") */

}
