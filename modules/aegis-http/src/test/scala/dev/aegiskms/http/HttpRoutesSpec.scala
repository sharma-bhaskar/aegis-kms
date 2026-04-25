package dev.aegiskms.http

import cats.effect.unsafe.IORuntime
import dev.aegiskms.core.KeyService
import io.circe.parser.parse
import org.apache.pekko.http.scaladsl.model.*
import org.apache.pekko.http.scaladsl.model.headers.RawHeader
import org.apache.pekko.http.scaladsl.server.Route
import org.apache.pekko.http.scaladsl.testkit.ScalatestRouteTest
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** End-to-end HTTP tests for the v1 keys surface using pekko-http's test-kit.
  *
  * Each test gets a fresh in-memory `KeyService` and a fresh `Route`, so tests are independent and order
  * doesn't matter.
  */
final class HttpRoutesSpec extends AnyFunSuite with Matchers with ScalatestRouteTest:

  private given IORuntime = IORuntime.global

  private def freshRoute(): Route =
    HttpRoutes(KeyService.inMemory.unsafeRunSync()).routes

  private val createBody =
    """{"spec":{"name":"invoice-signing","algorithm":"AES","sizeBits":256,"objectType":"SymmetricKey"}}"""

  private def jsonEntity(body: String): RequestEntity =
    HttpEntity(ContentTypes.`application/json`, body)

  private def extractField(body: String, field: String): String =
    parse(body).toOption
      .flatMap(_.hcursor.downField(field).as[String].toOption)
      .getOrElse(fail(s"missing field '$field' in $body"))

  test("POST /v1/keys creates a PreActive key and returns 201") {
    Post("/v1/keys", jsonEntity(createBody)) ~> freshRoute() ~> check {
      status shouldBe StatusCodes.Created
      val body = responseAs[String]
      body should include(""""state":"PreActive"""")
      body should include(""""name":"invoice-signing"""")
    }
  }

  test("POST /v1/keys with unknown algorithm returns 400 InvalidField") {
    val bad =
      """{"spec":{"name":"x","algorithm":"NOT_A_THING","sizeBits":256,"objectType":"SymmetricKey"}}"""
    Post("/v1/keys", jsonEntity(bad)) ~> freshRoute() ~> check {
      status shouldBe StatusCodes.BadRequest
      val body = responseAs[String]
      body should include(""""code":"InvalidField"""")
    }
  }

  test("GET /v1/keys/{id} returns the same key after create") {
    val route = freshRoute()
    var id    = ""

    Post("/v1/keys", jsonEntity(createBody)) ~> route ~> check {
      status shouldBe StatusCodes.Created
      id = extractField(responseAs[String], "id")
    }

    Get(s"/v1/keys/$id") ~> route ~> check {
      status shouldBe StatusCodes.OK
      val body = responseAs[String]
      body should include(s""""id":"$id"""")
      body should include(""""state":"PreActive"""")
    }
  }

  test("GET /v1/keys/{unknown} returns 404 ItemNotFound") {
    Get("/v1/keys/does-not-exist") ~> freshRoute() ~> check {
      status shouldBe StatusCodes.NotFound
      val body = responseAs[String]
      body should include(""""code":"ItemNotFound"""")
    }
  }

  test("POST /v1/keys/{id}/activate transitions PreActive -> Active") {
    val route = freshRoute()
    var id    = ""

    Post("/v1/keys", jsonEntity(createBody)) ~> route ~> check {
      id = extractField(responseAs[String], "id")
    }

    Post(s"/v1/keys/$id/activate") ~> route ~> check {
      status shouldBe StatusCodes.OK
      val body = responseAs[String]
      body should include(""""state":"Active"""")
    }

    Get(s"/v1/keys/$id") ~> route ~> check {
      val body = responseAs[String]
      body should include(""""state":"Active"""")
    }
  }

  test("DELETE /v1/keys/{id} removes the key (subsequent GET → 404)") {
    val route = freshRoute()
    var id    = ""

    Post("/v1/keys", jsonEntity(createBody)) ~> route ~> check {
      id = extractField(responseAs[String], "id")
    }

    Delete(s"/v1/keys/$id") ~> route ~> check {
      status shouldBe StatusCodes.NoContent
    }

    Get(s"/v1/keys/$id") ~> route ~> check {
      status shouldBe StatusCodes.NotFound
    }
  }

  test("X-Aegis-User header is accepted (placeholder principal mapping)") {
    val req = Post("/v1/keys", jsonEntity(createBody))
      .withHeaders(RawHeader("X-Aegis-User", "alice"))
    req ~> freshRoute() ~> check {
      status shouldBe StatusCodes.Created
    }
  }
