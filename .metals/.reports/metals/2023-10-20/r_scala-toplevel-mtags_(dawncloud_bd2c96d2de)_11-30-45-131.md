id: file://<WORKSPACE>/src/xyz/didx/Crypto.scala:[13158..13161) in Input.VirtualFile("file://<WORKSPACE>/src/xyz/didx/Crypto.scala", "package xyz.didx

import java.security.KeyStore
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Key

import cats.implicits._
import cats.effect.IO

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.security.KeyStore.TrustedCertificateEntry
import java.util.Base64
import java.security.PublicKey
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.*
import com.nimbusds.jose.jwk.JWKSet
import java.nio.file.Paths
import java.io.FileOutputStream
import java.io.FileInputStream
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import java.math.BigInteger
import java.util.Date
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import scala.util.Try
import scala.util.{Success, Failure}
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import java.security.PrivateKey
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.KDFParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECPoint
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.GCMParameterSpec
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import scala.annotation.tailrec


object Crypto:
  val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
  val IV_SIZE           = 12  // bytes
  val TAG_SIZE          = 128 // bits

  Security.addProvider(new BouncyCastleProvider())
  // if the keystore file does not exist, create a new keystore file
 
  // create a java keystore object

  def createKeyStore(password: String, keystorePath: String): IO[Either[Error, KeyStore]] = IO {
    val keyStore = KeyStore.getInstance("JKS")
    Try {
      keyStore.load(null, password.toCharArray)
      val keystoreFile         = Paths.get(keystorePath).toFile
      val keystoreOutputStream = new FileOutputStream(keystoreFile)
      keyStore.store(keystoreOutputStream, password.toCharArray)
      keystoreOutputStream.close()
    } match
      case Success(_)         => keyStore.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[KeyStore]
  }

  def loadKeyStore(password: String, keystorePath: String): IO[Either[Error, KeyStore]] = IO {
    val keyStore = KeyStore.getInstance("JKS")
    Try {
      val keystoreFile        = Paths.get(keystorePath).toFile
      val keystoreInputStream = new FileInputStream(keystoreFile)
      keyStore.load(keystoreInputStream, password.toCharArray)
      keystoreInputStream.close()
    } match
      case Success(_)         => keyStore.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[KeyStore]
  }

  // create a RSA key pair using java.security.KeyPairGenerator
  def createRSAKeyPair(): IO[Either[Error, KeyPair]] = IO {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
    keyPairGenerator.initialize(2048)
    Try {
      keyPairGenerator.generateKeyPair()
    } match
      case Success(keyPair)   => keyPair.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[KeyPair]
  }

  def createEd25519KeyPair(alias:String): IO[Either[Error, KeyPair]] = IO {
      val keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", "BC")
      Try {
        keyPairGenerator.generateKeyPair()
      } match
        case Success(keyPair)   => keyPair.asRight[Error]
        case Failure(exception) => Error(exception.getMessage()).asLeft[KeyPair]

    }


  // create a ED525519 key pair using net.i2p.crypto.eddsa.EdDSASecurityProvider
  def createKeyPair(alias: String): IO[Either[Error, OctetKeyPair]] =
    for {
      // keyStore <- getKeyStore("password", keystorePath)
      jwk <- Try {
               new OctetKeyPairGenerator(Curve.Ed25519)
                 .keyID(alias)
                 .generate()

             } match
               case Success(jwk)       => IO(jwk.asRight[Error])
               case Failure(exception) => IO(Error(exception.getMessage()).asLeft[OctetKeyPair])

    } yield jwk

  // create a EC P-384 key pair
  def createKeyPairECP384(alias: String): IO[Either[Error, ECKey]] =
    for {
      // keyStore <- getKeyStore("password", keystorePath)
      jwk <- Try {
               new ECKeyGenerator(Curve.P_384).keyID(alias).generate()

               // new ECKeyGenerator(Curve.P_384).keyID(alias).generate()
             } match
               case Success(jwk)       => IO(jwk.asRight[Error])
               case Failure(exception) => IO(Error(exception.getMessage()).asLeft[ECKey])

    } yield jwk // .computeThumbprint().toString()

  // save the JWKSet to a file
  

  // store the private key keystore
 

 

  // get the private key from keystore
  def getPrivateKey(keyStore: KeyStore, alias: String, password: String): IO[Either[Error, Key]] = IO {
    Try {
      keyStore.getKey(alias, password.toCharArray())
    } match
      case Success(key)       => key.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[Key]
  }

  // encrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string
  def decryptMessage(encryptedMessage: String, privateKey: ECPrivateKey): IO[Either[Error, String]] = IO {

    Try {
      val jweObject = JWEObject.parse(encryptedMessage)
      jweObject.decrypt(new ECDHDecrypter(privateKey))
      jweObject.getPayload().toString()
    } match
      case Success(message)   => message.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[String]

  }

  def encryptMessage(message: String, publicKey: ECPublicKey): IO[Either[Error, String]] = IO {
    Try {
      val o = new JWEObject(
        new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, com.nimbusds.jose.EncryptionMethod.A256GCM)
          .keyID(publicKey.toString())
          .build(),
        new Payload(message)
      )
      o.encrypt(new ECDHEncrypter(publicKey))
      o.serialize()
    } match
      case Success(s)         => s.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[String]
  }

//sign message using nimbus-jose-jwt library and return the signed message as base64 string
  def signMessage(message: String, privateKey: ECPrivateKey): IO[Either[Error, String]] = IO {
    Try {
      val jwsObject = new JWSObject(
        new JWSHeader.Builder(JWSAlgorithm.ES384).keyID(privateKey.toString()).build(),
        new Payload(message)
      )
      jwsObject.sign(new ECDSASigner(privateKey))
      jwsObject.serialize()
    } match
      case Success(s)         => s.asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[String]
  }

//validate the signature of the message using nimbus-jose-jwt library and return the boolean value
  def validateSignature(message: String, publicKey: ECPublicKey): IO[Either[Error, String]] = IO {
    val jwsObject = JWSObject.parse(message)
    Try(jwsObject.verify(new ECDSAVerifier(publicKey))) match
      case Success(_)         => jwsObject.getPayload().toString().asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[String]
  }

  // decrypt the message using nimbus-jose-jwt library and return the encrypted message as base64 string
  /*  def decryptMessage(message: String, privateKey: ECPrivateKey): IO[Either[Error, String]] = IO {
    val jweObject = JWEObject.parse(message)
    Try(jweObject.decrypt(new ECDHDecrypter(privateKey))) match
      case Success(_)         => jweObject.getPayload().toString().asRight[Error]
      case Failure(exception) => Error(exception.getMessage()).asLeft[String]
  } */

  // derive symmetric key using nimbus-jose-jwt library and return the key as base64 string

  def createSelfSignedCertificate(alias: String): IO[Either[Error, X509Certificate]] = IO {
    Try {
      Security.addProvider(new BouncyCastleProvider())
      val keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
      keyPairGenerator.initialize(2048)
      val keyPair          = keyPairGenerator.generateKeyPair()
      val subject          = new X500Name(s"CN=$alias")
      val issuer           = subject
      val serialNumber     = BigInteger.valueOf(System.currentTimeMillis())
      val notBefore        = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000) // 1 day ago
      val notAfter         =
        new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000) // 1 year from now
      val pubKey        =
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded)
      val publicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(pubKey)
      val certBuilder   = new X509v3CertificateBuilder(
        issuer,
        serialNumber,
        notBefore,
        notAfter,
        subject,
        publicKeyInfo
      )
      val contentSigner = JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate())
      val certHolder    = certBuilder.build(contentSigner)
      val certConverter = JcaX509CertificateConverter()
      certConverter.getCertificate(certHolder)
    } match
      case Success(certificate) => certificate.asRight[Error]
      case Failure(exception)   => Error(exception.getMessage()).asLeft[X509Certificate]
  }

  def storeCertificate(
    keyStore: KeyStore,
    certificate: X509Certificate,
    alias: String,
    password: Array[Char]
  ): IO[Either[Error, Unit]] =
    IO {
      Try {
        keyStore.setCertificateEntry(alias, certificate)
      } match
        case Success(_)         => ().asRight[Error]
        case Failure(exception) => Error(exception.getMessage()).asLeft[Unit]
    }
    // Save the keystore to a file or perform any other necessary operations

  def getPublicKeyFromBase64(base64String: String): IO[Either[Exception, PublicKey]] =
    val keyBytes   = Base64.getDecoder.decode(base64String)
    val keySpec    = new X509EncodedKeySpec(keyBytes)
    val keyFactory = KeyFactory.getInstance("EdDSA")
    IO(keyFactory.generatePublic(keySpec).asRight[Exception])

  def getECPublicKeyFromBase58(base58String: String): IO[Either[Exception, ECPublicKey]] =
    val keyBytes   = Crypto.decodeFromBase58(base58String)
    val keySpec    = new X509EncodedKeySpec(keyBytes)
    val keyFactory = KeyFactory.getInstance("EC")
    IO(keyFactory.generatePublic(keySpec).asInstanceOf[ECPublicKey].asRight[Exception])

  def computeSharedSecret(
    peerPublicKey: org.bouncycastle.jce.interfaces.ECPublicKey,
    myPrivateKey: org.bouncycastle.jce.interfaces.ECPrivateKey,
    nonce: Array[Byte]
  ): IO[Either[Error, Array[Byte]]] =
    IO {
      Try {
        val agreement        = new ECDHBasicAgreement()
        val curveParams      = ECNamedCurveTable.getParameterSpec("secp256r1")
        val domainParams     =
          new ECDomainParameters(curveParams.getCurve(), curveParams.getG(), curveParams.getN(), curveParams.getH())
        val privateKeyParams = new ECPrivateKeyParameters(myPrivateKey.getD(), domainParams)
        agreement.init(privateKeyParams)

        val pubKeyParams       = new ECPublicKeyParameters(peerPublicKey.getQ(), domainParams)
        val sharedSecretBigInt = agreement.calculateAgreement(pubKeyParams)

        // Convert shared secret to bytes
        val sharedSecretBytes = sharedSecretBigInt.toByteArray

        // Derive AES key using KDF (with nonce/salt)
        val kdf = new KDF2BytesGenerator(new SHA256Digest())
        kdf.init(new KDFParameters(sharedSecretBytes, nonce))

        val aesKey = new Array[Byte](32) // For AES-256
        kdf.generateBytes(aesKey, 0, aesKey.length)
        aesKey
      } match
        case Success(s)         => s.asRight[Error]
        case Failure(exception) => Error(exception.getMessage()).asLeft[Array[Byte]]
    }

  def encrypt(key: Array[Byte], plaintext: String): IO[Either[Error, (String, String)]] = IO {
    Try {
      val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
      val iv     = new Array[Byte](IV_SIZE)
      new java.security.SecureRandom().nextBytes(iv)
      val spec   = new GCMParameterSpec(TAG_SIZE, iv)
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec)

      val ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"))
      (Base64.getEncoder.encodeToString(ciphertext), Base64.getEncoder.encodeToString(iv))
    } match {
      case Success(value)     => Right(value)
      case Failure(exception) => Left(Error(exception.getMessage))
    }
  }

  def

  def decrypt(key: Array[Byte], ciphertext: String, ivStr: String): IO[Either[Error, String]] = IO {
    Try {
      val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
      val spec   = new GCMParameterSpec(TAG_SIZE, Base64.getDecoder.decode(ivStr))
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec)

      val decrypted = cipher.doFinal(Base64.getDecoder.decode(ciphertext))
      new String(decrypted, "UTF-8")
    } match {
      case Success(value)     => Right(value)
      case Failure(exception) => Left(Error(exception.getMessage))
    }
  }

  def makeDidKey(kty: String, crv: String, pubKey: PublicKey): Option[String] =
     val algo = xyz.didx.Algorithm(kty, crv)
     val key: Option[String] = pubKey.getEncoded() match
       case b: Array[Byte] => Some(encodeToBase58(b))
       case null           => None
     (algo, key) match
       case (a, Some(k)) => Some(s"did:key:${a}$k")
       case _            => None

  val alphabetBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  val idxToChar = Map(alphabetBase58.zipWithIndex.map(_.swap): _*)

  val charToIdx = Map(alphabetBase58.zipWithIndex: _*)

  def encodeToBase58(array: Array[Byte]): String =
    (LazyList.fill(array.takeWhile(_ == 0).length)(1.toByte) ++ LazyList
      .unfold(
        BigInt(0.toByte +: array)
      )(n => if (n == 0) None else Some((n /% 58).swap))
      .map(_.toInt)
      .reverse
      .map(x => idxToChar(x))).mkString

  def decodeFromBase58(b58: String): Array[Byte] = {
    val zeroCount = b58.takeWhile(_ == '1').length
    Array.fill(zeroCount)(0.toByte) ++
      b58
        .drop(zeroCount)
        .map(charToIdx)
        .toList
        .foldLeft(BigInt(0))((acc, x) => acc * 58 + x)
        .toByteArray
        .dropWhile(_ == 0.toByte)
  }
  def encodeB58(input: Seq[Byte]): String = {
     if (input.isEmpty) ""
     else {
       val big = new BigInteger(1, input.toArray)
       val builder = new StringBuilder

       @tailrec
       def encode1(current: BigInteger): Unit = current match {
         case BigInteger.ZERO => ()
         case _ =>
           val Array(x, remainder) = current.divideAndRemainder(BigInteger.valueOf(58L))
           builder.append(alphabetBase58.charAt(remainder.intValue))
           encode1(x)
       }
       encode1(big)
       input.takeWhile(_ == 0).map(_ => builder.append(alphabetBase58.charAt(0)))
       builder.toString().reverse
     }
   }")
file://<WORKSPACE>/src/xyz/didx/Crypto.scala
file://<WORKSPACE>/src/xyz/didx/Crypto.scala:327: error: expected identifier; obtained def
  def decrypt(key: Array[Byte], ciphertext: String, ivStr: String): IO[Either[Error, String]] = IO {
  ^
#### Short summary: 

expected identifier; obtained def