package xyz.didx

import cats.effect.*
import cats.syntax.all.*
import cats.implicits.*

import com.monovore.decline.*
import com.monovore.decline.effect.*
import io.circe.parser.*
import io.circe.syntax.*
import java.util.concurrent.CompletableFuture
import cats.data.EitherT
import scala.jdk.CollectionConverters._
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
