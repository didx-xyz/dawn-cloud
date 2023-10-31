id: file://<WORKSPACE>/src/xyz/didx/DawnCloud.scala:[1892..1892) in Input.VirtualFile("file://<WORKSPACE>/src/xyz/didx/DawnCloud.scala", "package xyz.didx

import cats.effect.*
import cats.syntax.all.*
import cats.implicits.*

import com.monovore.decline.*
import com.monovore.decline.effect.*
import io.circe.parser.*
import io.circe.syntax.*
import didcomm.*
import io.ipfs.api.*
import java.util.concurrent.CompletableFuture
import cats.data.EitherT
import scala.jdk.CollectionConverters._
import io.ipfs.multihash.Multihash
import scala.util.Try
import didcomm.DIDCodec.decodeDIDDoc
import didcomm.DIDCodec.encodeDIDDoc
import scala.concurrent.ExecutionContext

object DawnCloud extends IOApp:
  // given logger[F[_]: Sync]: Logger[F] = Slf4jLogger.getLogger[F]
  given logger: org.log4s.Logger = org.log4s.getLogger
  given ec: ExecutionContext =
    scala.concurrent.ExecutionContext.Implicits.global

  // DawnCloud Registrar and Resolver API  for did:web and did:key methods
  // register a did:web

  //register a did:key
  //resolve a did:web
  //resolve a did:key

  // create a DIDDoc using DIDCodec
  def createDIDDocument(
       did: String,
       controller: String,
       verificationMethod: VerificationMethod,
       service: Service
   ): DIDDoc =
     DIDDoc(
       did,
       Some(controller),
       None,
       Some(Set(verificationMethod)),
       None,
       None,
       None,
       None,
       None,
       Some(Set(service))
     )

  
  // write to IPFS
  def writeIPFS(didDoc: DIDDoc): IO[Either[Error, Multihash]] = 
      val json =  didDoc.asJson.noSpaces
     
      val result = (for 
        ipfs <-  EitherT(IO( new IPFS("/ip4/127.0.0.1/tcp/5001")).attempt)// Replace with your IPFS HTTP API endpoint URL
        ns <- EitherT(IO(new NamedStreamable.ByteArrayWrapper(json.getBytes)).attempt)
        cf <-  EitherT(IO(ipfs.add(ns).asScala.toList.head).attempt)
        pn <- EitherT(IO(cf.hash).attempt)
      yield pn).value.map(_.leftMap(Error(_)))
      result

      
  def
  
  
")
file://<WORKSPACE>/src/xyz/didx/DawnCloud.scala
file://<WORKSPACE>/src/xyz/didx/DawnCloud.scala:72: error: expected identifier; obtained eof

^
#### Short summary: 

expected identifier; obtained eof