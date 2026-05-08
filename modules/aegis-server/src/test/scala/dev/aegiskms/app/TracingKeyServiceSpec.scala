package dev.aegiskms.app

import cats.effect.unsafe.implicits.global
import dev.aegiskms.core.*
import io.opentelemetry.api.trace.{StatusCode, Tracer}
import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter
import io.opentelemetry.sdk.trace.SdkTracerProvider
import io.opentelemetry.sdk.trace.`export`.SimpleSpanProcessor
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

import scala.jdk.CollectionConverters.*

/** Tests `TracingKeyService` against the OTel `InMemorySpanExporter`. We avoid the global SDK so each test
  * gets a fresh exporter; spans the decorator emits land in the in-memory list and we assert on names +
  * attributes + statuses without touching network exporters.
  */
final class TracingKeyServiceSpec extends AnyFunSuite with Matchers:

  private val alice: Principal = Principal.Human("alice@org", Set("admins"))

  private def fixture(): (TracingKeyService, InMemorySpanExporter) =
    val exporter = InMemorySpanExporter.create()
    val provider = SdkTracerProvider.builder()
      .addSpanProcessor(SimpleSpanProcessor.create(exporter))
      .build()
    val sdk: OpenTelemetrySdk = OpenTelemetrySdk.builder().setTracerProvider(provider).build()
    val tracer: Tracer        = sdk.getTracer("aegis-kms-test")
    val inner                 = KeyService.inMemory.unsafeRunSync()
    (new TracingKeyService(inner, tracer), exporter)

  test("a successful create emits one span named kms.create with success outcome") {
    val (svc, exporter) = fixture()
    svc.create(KeySpec.aes256("k"), alice).unsafeRunSync()

    val spans = exporter.getFinishedSpanItems.asScala
    spans.size shouldBe 1
    val span = spans.head
    span.getName shouldBe "kms.create"
    span.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.operation")
    ) shouldBe "Create"
    span.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.outcome")
    ) shouldBe "success"
    span.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.principal.subject")
    ) shouldBe "alice@org"
    span.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.principal.kind")
    ) shouldBe "human"
  }

  test("a failing call (sign on PreActive) sets span status ERROR with the KmsError message") {
    val (svc, exporter) = fixture()
    val k               = svc.create(KeySpec.rsa2048("k"), alice).unsafeRunSync().toOption.get
    // Skip activate so sign returns IllegalOperation
    svc.sign(k.id, "x".getBytes, SigAlgorithm.RsaPssSha256, alice).unsafeRunSync()

    val signSpan = exporter.getFinishedSpanItems.asScala.find(_.getName == "kms.sign").get
    signSpan.getStatus.getStatusCode shouldBe StatusCode.ERROR
    signSpan.getStatus.getDescription should include("Active")
    signSpan.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.outcome")
    ) shouldBe "error_IllegalOperation"
    // The detail attribute carries the algorithm for sign / verify.
    signSpan.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.detail")
    ) shouldBe "RsaPssSha256"
  }

  test("each call emits a separate span; key id is stamped where applicable") {
    val (svc, exporter) = fixture()
    val k               = svc.create(KeySpec.aes256("k"), alice).unsafeRunSync().toOption.get
    svc.activate(k.id, alice).unsafeRunSync()
    svc.get(k.id, alice).unsafeRunSync()

    val spans = exporter.getFinishedSpanItems.asScala.toList
    spans.map(_.getName).sorted shouldBe List("kms.activate", "kms.create", "kms.get")
    val getSpan = spans.find(_.getName == "kms.get").get
    getSpan.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.key.id")
    ) shouldBe k.id.value
  }

  test("locate emits one span with the hit count regardless of result size") {
    val (svc, exporter) = fixture()
    svc.locate("nope", alice).unsafeRunSync() shouldBe Nil
    val span = exporter.getFinishedSpanItems.asScala.find(_.getName == "kms.locate").get
    span.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.longKey("aegis.locate.hits")
    ).longValue shouldBe 0L
  }

  test("rotate's policy.render is captured as the detail attribute") {
    val (svc, exporter) = fixture()
    val k               = svc.create(KeySpec.aes256("k"), alice).unsafeRunSync().toOption.get
    svc.activate(k.id, alice).unsafeRunSync()
    svc.rotate(k.id, RotationPolicy.Manual, alice).unsafeRunSync()

    val rotateSpan = exporter.getFinishedSpanItems.asScala.find(_.getName == "kms.rotate").get
    rotateSpan.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.detail")
    ) shouldBe "Manual"
    rotateSpan.getAttributes.get(
      io.opentelemetry.api.common.AttributeKey.stringKey("aegis.outcome")
    ) shouldBe "success"
  }
