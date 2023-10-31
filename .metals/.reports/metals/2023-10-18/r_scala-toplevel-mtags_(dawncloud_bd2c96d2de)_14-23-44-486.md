id: file://<WORKSPACE>/src/xyz/didx/DIDDoc.scala:[803..807) in Input.VirtualFile("file://<WORKSPACE>/src/xyz/didx/DIDDoc.scala", "package xyz.didx

import io.circe.generic.auto.*
import sttp.tapir.generic.auto.*
import sttp.tapir.json.circe.*
import sttp.tapir.Schema
import io.circe.*
import io.circe.syntax.*

enum DID(did: String):
    case DIDWeb(did: String) extends DID(did)
    case DIDKey(did: String) extends DID(did)
    case DIDUnknown(did: String) extends DID(did)

    def getDIDMethod: String = did.split(":")(1)
    def getDIDMethodSpecificId: String = did.split(":")(2)
    def setDIDMethodSpecificId(id: String): DID = id match
        case id if id.startsWith("http") => DIDWeb(s"did:web:$id")
        case id => DIDKey(s"did:key:$id")

object DID:
   def apply(did: String): DID = did.split(":")(1) match
        case "web" => DIDWeb(did)
        case "key" => DIDKey(did)
        case _ => DIDUnknown(did)
enum 

case class DIDDoc(`@context`: List[String] = List("https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/security/suites/x25519-2020/v1"),
    id: String = "did:web", 
    controller:List[String] = List.empty[String])
 
given didDocDecoder: Decoder[DIDDoc] = new Decoder[DIDDoc] {
    final def apply(c: HCursor): Decoder.Result[DIDDoc] =
        for {
        context <- c.downField("@context").as[List[String]]
        id <- c.downField("id").as[String]
        controller <- c.downField("controller").as[List[String]]
        } yield {
        DIDDoc(context, id, controller)
        }
    }
given didDocEncoder: Encoder[DIDDoc] = new Encoder[DIDDoc] {
    final def apply(a: DIDDoc): Json = Json.obj(
        ("@context", a.`@context`.asJson),
        ("id", a.id.asJson),
        ("controller", a.controller.asJson)
    )
}
")
file://<WORKSPACE>/src/xyz/didx/DIDDoc.scala
file://<WORKSPACE>/src/xyz/didx/DIDDoc.scala:28: error: expected identifier; obtained case
case class DIDDoc(`@context`: List[String] = List("https://www.w3.org/ns/did/v1",
^
#### Short summary: 

expected identifier; obtained case