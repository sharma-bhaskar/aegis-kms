package dev.aegiskms.kmip

/** SPI for KMIP codec implementations. Aegis-KMS will ship a reference codec for KMIP 1.4 and 2.x; this trait
  * is the integration seam for alternate implementations or for versions we haven't yet added.
  *
  * Placeholder during scaffolding. The real codec replaces the `Kmip.jar` local jar from the legacy uKM
  * project.
  */
trait KmipCodec:
  def decodeRequest(bytes: Array[Byte]): Either[String, KmipRequest]
  def encodeResponse(response: KmipResponse): Array[Byte]

final case class KmipRequest(operation: Int, payload: Map[String, AnyRef])
final case class KmipResponse(operation: Int, status: Int, payload: Map[String, AnyRef])
