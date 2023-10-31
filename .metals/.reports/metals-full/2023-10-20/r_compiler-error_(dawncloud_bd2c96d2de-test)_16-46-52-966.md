file://<WORKSPACE>/test/CryptoSpec.test.scala
### java.lang.AssertionError: assertion failed

occurred in the presentation compiler.

action parameters:
offset: 4533
uri: file://<WORKSPACE>/test/CryptoSpec.test.scala
text:
```scala
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


class CryptoSpec  extends CatsEffectSuite {

// RSA Key
  test("Generate an RSA KeyPair") {
    val x = (for {
      keyPair <- EitherT.right(IO(new RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(new Date()) // issued-at timestamp (optional)
        .generate()))
       json <- EitherT(IO(parse(keyPair.toPublicJWK().toJSONString())))
       _ <- EitherT.right(IO.println(json.spaces2))

    } yield keyPair).value
    x.unsafeRunSync()
  

  }
  test("Generate an ED25519") {
      val x = (for {
        keyPair <- EitherT.right(IO(new OctetKeyPairGenerator(Curve.Ed25519)
            .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
            .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
            .issueTime(new Date()) // issued-at timestamp (optional)
            .generate()))
         json <- EitherT(IO(parse(keyPair.toPublicJWK().toJSONString())))
         _ <- EitherT.right(IO.println(json.spaces2))
      }
        yield keyPair).value
        x.unsafeRunSync()
    }
  test("Generate an X25519") {
        val x = (for {
            keyPair <- EitherT.right(IO(new OctetKeyPairGenerator(Curve.X25519)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(new Date()) // issued-at timestamp (optional)
                .generate()))
             //kp <- EitherT.right(IO(keyPair.toKeyPair()))
             json <- EitherT(IO(parse(keyPair.toPublicJWK().toJSONString())))
             _ <- EitherT.right(IO.println(json.spaces2))
             pk <- EitherT.right(IO(Jwks.parser.build.parse(json.noSpaces).toKey))
              _ <- EitherT.right(IO.println(pk.toString()))
             _ <- EitherT.right(IO.println(json.spaces2))
            // dec <- EitherT.rightT(Base64.getUrlDecoder().decode("haXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"))
             pubkey <- EitherT.fromEither(json.hcursor.downField("x").as[String])
             _ <- EitherT.right(IO.println(s"pubkey: ${pubkey} - length: ${pubkey.size}"))
             //b58 <- EitherT.rightT(encodeToBase58(Base64.getUrlDecoder.decode(pubkey)))
            // key <- EitherT((getECPublicKeyFromBase58(b58)))
             key <- EitherT((getECPublicKey(pubkey)))

             enc <- EitherT(encrypt(key, "hello world"))
             _ <- EitherT.right(IO.println(s"\nEncrypted ${enc._1} "))

             dec <- EitherT.rightT(decrypt(keyPair.toPrivateKey(), enc._1, "AES/GCM/NoPadding"))

             _ <- EitherT.right(IO.println(s" \nDecrypted: ${dec}"))
             // _ <- EitherT.right(IO.println(s"Base58Str: ${b58} - length: ${b58.size}"))
        }
            yield keyPair).value
            x.unsafeRunSync()
        }
  test("Generate an EC P384") {
            val x = (for {
               /*  ecKey <- EitherT.right(IO(new ECKeyGenerator(Curve.P_384)
                    .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                    .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                    .issueTime(new Date()) // issued-at timestamp (optional)
                    .generate())) */
                 ecKey <- EitherT.right(IO(new ECKeyGenerator(Curve.P_384)
                                     .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                                     .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                                     .issueTime(new Date()) // issued-at timestamp (optional)
                                     .generate()))
                 keyPair: KeyPair <- EitherT.right(IO(ecKey.toKeyPair()))
                 json <- EitherT(IO(parse(ec.@@toJSONString())))

                 ecpkey: EcPrivateJwk <- EitherT.right(IO(Jwks.builder().ecKeyPair(keyPair).build()))


                 b641 <- EitherT.right(IO(ecKey.getX()))
                 b642 <- EitherT.right(IO(ecKey.getY()))

                 pk <- EitherT.right(IO(Crypto.encodeToBase58(b641.decode)))
                 pk2 <- EitherT.right(IO(Crypto.encodeToBase58(keyPair.getPublic().getEncoded())))


                 _ <- EitherT.right(IO.println(s"Base64:${new String(b641.decodeToString())} - length = ${b641.decodeToString().size} \n $pk - length: ${pk.size}\n\n"))
                 _ <- EitherT.right(IO.println(s"KeyPair: ${keyPair.getPublic.toString()} - length: ${keyPair.getPublic.toString().size} \n${pk2} - length: ${pk2.size}"))

                 json <- EitherT(IO(parse(ecKey.toPublicJWK().toJSONString())))
                 js <- EitherT(IO(json.hcursor.downField("x").as[String]))
                 _ <- EitherT.right(IO.println(json.spaces2))
                 _ <- EitherT.right(IO.println(s"x: $js - length: ${js.size}"))
                 _ <- EitherT.right(IO.println(s"${ecpkey.toPublicJwk()} - length: ${ecpkey.toKeyPair().getPublic().getW().getAffineX().bitCount()/8}"))
                              



            }
                yield ecKey).value
                x.unsafeRunSync()
            }

     test("jjwt") {
       // val key = Jwks.builder

     }

  }



```



#### Error stacktrace:

```
scala.runtime.Scala3RunTime$.assertFailed(Scala3RunTime.scala:11)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:45)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.MetalsInteractive$.contextOfPath(MetalsInteractive.scala:31)
	scala.meta.internal.pc.AutoImportsProvider.autoImports(AutoImportsProvider.scala:47)
	scala.meta.internal.pc.ScalaPresentationCompiler.autoImports$$anonfun$1(ScalaPresentationCompiler.scala:216)
```
#### Short summary: 

java.lang.AssertionError: assertion failed