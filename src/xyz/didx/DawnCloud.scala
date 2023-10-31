package xyz.didx

import cats.effect.*
import cats.syntax.all.*
import cats.implicits.*

import com.monovore.decline.*
import com.monovore.decline.effect.*
import io.circe.parser.*
import io.circe.syntax.*
import io.ipfs.api.*
import java.util.concurrent.CompletableFuture
import cats.data.EitherT
import scala.jdk.CollectionConverters._
import io.ipfs.multihash.Multihash
import scala.util.Try

import scala.concurrent.ExecutionContext
import sttp.tapir.*
import io.circe.generic.auto.*

import sttp.tapir.json.circe.*
import sttp.tapir.generic.auto.*
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.Router
import io.circe.Encoder
import org.http4s.HttpRoutes
import sttp.tapir.server.http4s.Http4sServerInterpreter
import com.comcast.ip4s.{Host, Port, port}

object DawnCloud extends IOApp:

  // DawnCloud Registrar and Resolver API  for did:web and did:key methods

  // resolve a did:web
  // resolve a did:key

  // create a DIDDoc using DIDCodec
  override def run(args: List[String]): IO[ExitCode] =

    val routes = Http4sServerInterpreter[IO]().toRoutes(Endpoints.all)

    val port = sys.env
      .get("HTTP_PORT")
      .flatMap(_.toIntOption)
      .flatMap(Port.fromInt)
      .getOrElse(port"8080")

    EmberServerBuilder
      .default[IO]
      .withHost(Host.fromString("localhost").get)
      .withPort(port)
      .withHttpApp(Router("/" -> routes).orNotFound)
      .build
      .use { server =>
        for {
          _ <- IO.println(
                 s"Go to http://localhost:${server.address.getPort}/docs to open SwaggerUI. Press ENTER key to exit."
               )
          _ <- IO.readLine
        } yield ()
      }
      .as(ExitCode.Success)

  // write to IPFS
  def writeIPFS(didDoc: DIDDoc): IO[Either[Error, Multihash]] =
    val json = didDoc.asJson.noSpaces

    val result = (for
      ipfs <- EitherT(IO(new IPFS("/ip4/127.0.0.1/tcp/5001")).attempt) // Replace with your IPFS HTTP API endpoint URL
      ns   <- EitherT(IO(new NamedStreamable.ByteArrayWrapper(json.getBytes)).attempt)
      cf   <- EitherT(IO(ipfs.add(ns).asScala.toList.head).attempt)
      pn   <- EitherT(IO(cf.hash).attempt)
    yield pn).value.map(_.leftMap(Error(_)))
    result
