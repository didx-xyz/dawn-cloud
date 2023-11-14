package xyz.didx

import cats.effect.*
import sttp.tapir.*
import sttp.tapir.generic.auto.*

import sttp.tapir.server.ServerEndpoint
import sttp.tapir.swagger.bundle.SwaggerInterpreter
import sttp.tapir.json.circe.*
import sttp.tapir.generic.auto.*
import io.circe.Encoder.AsArray.importedAsArrayEncoder
import io.circe.Encoder.AsObject.importedAsObjectEncoder
import io.circe.Encoder.AsRoot.importedAsRootEncoder
import xyz.didx.DIDDoc
import scala.util.*

import sttp.tapir.Codec.PlainCodec
import java.util.concurrent.ConcurrentHashMap.KeySetView

object Endpoints:
  enum DidMethod:
    case Key   extends DidMethod
    case Web   extends DidMethod
    case Peer  extends DidMethod
    case Other extends DidMethod

    override def toString(): String = this match
      case Key   => "key"
      case Web   => "web"
      case Peer  => "peer"
      case Other => "other"
  object DidMethod:
    def apply(s: String): DidMethod = s match
      case "key"  => Key
      case "web"  => Web
      case "peer" => Peer
      case _      => Other

  enum KeyType:
    case Ed25519
    case X25519
    case P256
    case P384
    case P521
    case RSA2048
    case RSA4096

  type ErrorInfo = String

  case class KeySet(
    id: String,
    `type`: KeyType,
    controller: String,
    publicKeyBase58: String,
    privateKeyBase58: String
  )

  // register a did:web by providing a tapir endpoint
  val registerEndpoint: PublicEndpoint[(String, String), String, DIDDoc, Any] =
    endpoint.post
      .in("register")
      .in(path[String]("method"))
      .in(stringJsonBody)
      .out(jsonBody[DIDDoc])
      .errorOut(plainBody[ErrorInfo])

  // register a did:web by providing a tapir endpoint
  val resolveEndpoint: PublicEndpoint[String, String, DIDDoc, Any] =
    endpoint.get
      .in("resolve" / stringBody)
      // .in(query[String]("did"))
      .out(jsonBody[DIDDoc])
      .errorOut(plainBody[ErrorInfo])

  def handleLogicError[A](io: IO[Either[String, A]]): IO[Either[ErrorInfo, A]] =
    for {
      either <- io
    } yield either match
      case Left(error)  => Left(error)
      case Right(value) => Right(value)

  def registerLogic(method: (String, String)): IO[Either[String, DIDDoc]] = DidMethod(method._1) match
    case DidMethod.Web  =>
      IO(
        Right(DIDDoc(
          List(
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
          ),
          "did:web:didx.xyz/iandebeer",
          List("did:web:didx.xyz/iandebeer/diddoc.json")
        ))
      )
    case DidMethod.Key  =>
      IO(
        Right(DIDDoc(
          List(
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
          ),
          "did:key:123",
          List("did:key:123")
        ))
      )
    case DidMethod.Peer =>
      IO(
        Right(DIDDoc(
          List(
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/security/suites/x25519-2020/v1"
          ),
          "did:peer:123",
          List("did:peer:123")
        ))
      )
    case _              => IO(Left(s"$method: Unsupported method"))
  def resolverLogic(t: String): IO[Either[String, DIDDoc]]                = IO(Right(DIDDoc(
    List(
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
      "https://w3id.org/security/suites/x25519-2020/v1"
    ),
    "did:web:123",
    List("did:web:123")
  )))

  val registerServerEndpoint: ServerEndpoint[Any, IO] =
    registerEndpoint.serverLogic((registerLogic _).andThen(handleLogicError))
  val resolveServerEndpoint: ServerEndpoint[Any, IO]  =
    resolveEndpoint.serverLogic((resolverLogic _).andThen(handleLogicError))
  val apiEndpoints: List[ServerEndpoint[Any, IO]]     = List(registerServerEndpoint, resolveServerEndpoint)

  val docEndpoints: List[ServerEndpoint[Any, IO]] = SwaggerInterpreter()
    .fromServerEndpoints[IO](apiEndpoints, "DIDx Registrar and Resolver for did:peer, did:key and did:web", "1.0.0")

  val all: List[ServerEndpoint[Any, IO]] = apiEndpoints ++ docEndpoints
