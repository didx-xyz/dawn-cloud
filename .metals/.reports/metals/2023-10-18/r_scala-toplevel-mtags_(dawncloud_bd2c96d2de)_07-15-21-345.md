id: file://<WORKSPACE>/src/xyz/didx/Endpoints.scala:[913..917) in Input.VirtualFile("file://<WORKSPACE>/src/xyz/didx/Endpoints.scala", "package xyz.didx

import cats.effect.*
import sttp.tapir.*

import sttp.tapir.server.ServerEndpoint
import sttp.tapir.swagger.bundle.SwaggerInterpreter
import sttp.tapir.json.circe.*
import sttp.tapir.generic.auto.* 
import io.circe.Encoder.AsArray.importedAsArrayEncoder
import io.circe.Encoder.AsObject.importedAsObjectEncoder
import io.circe.Encoder.AsRoot.importedAsRootEncoder
import xyz.didx.DIDDoc


object Endpoints:

   
    
    enum DID(did: String):
        case DIDWeb(did: String) extends DID(did)
        case DIDKey(did: String) extends DID(did)
        case DIDUnknown(did: String) extends DID(did)
        def getDID: DID = did.split(":")(1) match
            case "web" => DIDWeb(did)
            case "key" => DIDKey(did)
            case _ => DIDUnknown(did)
        def getDIDMethod: String = did.split(":")(1)
        def getDIDMethodSpecificId: String = did.split(":")(2)
        def

    case class DIDDoc(
        context: List[String],
        id: String,
        verificationMethod: List[String]
    )   
    
  //register a did:key by providing a tapir endpoint
    val didKeyEndpoint: PublicEndpoint[String, Unit, DIDDoc, Any] = 
        endpoint.post
        .in("did" / "key")
        .in(stringJsonBody)
        .out(jsonBody[DIDDoc])

    //register a did:web by providing a tapir endpoint
    val didWebEndpoint: PublicEndpoint[String, Unit, DIDDoc, Any] =
        endpoint.post
        .in("did" / "web")
        .in(stringJsonBody)
        .out(jsonBody[DIDDoc])

       //register a did:web by providing a tapir endpoint
    val resolveDidEndpoint: PublicEndpoint[String, Unit, DIDDoc, Any] =
        endpoint.get
        .in("resolve" / "web")
        .in(query[String]("did"))

        .out(jsonBody[DIDDoc])

    val didKeyServerEndpoint: ServerEndpoint[Any, IO] = didKeyEndpoint.serverLogicSuccess(user => IO.pure(
        DIDDoc(
            List("https://www.w3.org/ns/did/v1",
               "https://w3id.org/security/suites/ed25519-2020/v1",
               "https://w3id.org/security/suites/x25519-2020/v1"),
            "did:key:123",
            List("did:key:123"))))
    val didWebServerEndpoint: ServerEndpoint[Any, IO] = didWebEndpoint.serverLogicSuccess(user => IO.pure(
        DIDDoc( List("https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/suites/ed25519-2020/v1",
                        "https://w3id.org/security/suites/x25519-2020/v1"),
                        "did:key:123")))



    val apiEndpoints: List[ServerEndpoint[Any, IO]] = List(didKeyServerEndpoint, didWebServerEndpoint)

    val docEndpoints: List[ServerEndpoint[Any, IO]] = SwaggerInterpreter()
    .fromServerEndpoints[IO](apiEndpoints, "DIDx Registrar and Resolver for did:key and did:web", "1.0.0")

    val all: List[ServerEndpoint[Any, IO]] = apiEndpoints ++ docEndpoints



")
file://<WORKSPACE>/src/xyz/didx/Endpoints.scala
file://<WORKSPACE>/src/xyz/didx/Endpoints.scala:32: error: expected identifier; obtained case
    case class DIDDoc(
    ^
#### Short summary: 

expected identifier; obtained case