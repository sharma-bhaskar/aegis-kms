package dev.aegiskms.app

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import com.typesafe.config.ConfigFactory
import dev.aegiskms.crypto.RootOfTrust
import dev.aegiskms.crypto.aws.AwsKmsRootOfTrust
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Unit tests for `Server.rootOfTrustResource`. Verifies the config-driven RoT selection that closes the "AWS
  * KMS shipped but not wired" gap surfaced in the v0.2.0 readiness audit.
  *
  * The aws-kms happy path is exercised only at the "we successfully built a RoT instance" level — actual AWS
  * calls are out of scope (the adapter itself is covered by `AwsKmsRootOfTrustSpec` in aegis-crypto). What we
  * test here is purely the boot-time selection logic.
  */
final class RootOfTrustResourceSpec extends AnyFunSuite with Matchers:

  given IORuntime = IORuntime.global

  // Reflectively invoke the private builder. The builder is private to keep operators from
  // reaching past Server.boot; tests need access to verify the selection logic.
  private val server = Server.getClass.getDeclaredMethod(
    "rootOfTrustResource",
    classOf[com.typesafe.config.Config]
  )
  server.setAccessible(true)
  private def invoke(cfg: com.typesafe.config.Config) =
    server.invoke(Server, cfg).asInstanceOf[cats.effect.Resource[IO, RootOfTrust[IO]]]

  // Build a Config from an inline HOCON string. Falls through to defaults from application.conf
  // for any keys not set so we don't have to re-specify the entire tree.
  private def cfg(hocon: String) =
    ConfigFactory.parseString(hocon).withFallback(ConfigFactory.load())

  test("kind=in-memory yields the dev RoT (NOT an AwsKmsRootOfTrust)") {
    // `RootOfTrust.inMemory` is a `def` that creates a fresh anonymous instance each call, so we
    // can't use `eq` for identity comparison. We assert by negative type — anything that isn't
    // `AwsKmsRootOfTrust` is the dev backend (in-memory is the only other production code path).
    val rot = invoke(cfg("""aegis.crypto.kind = "in-memory" """)).use(IO.pure).unsafeRunSync()
    rot shouldNot be(a[AwsKmsRootOfTrust])
  }

  test("kind defaults to in-memory when no override is set (application.conf default)") {
    val rot = invoke(cfg("")).use(IO.pure).unsafeRunSync()
    rot shouldNot be(a[AwsKmsRootOfTrust])
  }

  test("kind=aws-kms with region + kek-arn yields an AwsKmsRootOfTrust") {
    // The KmsClient connects lazily on the first SDK call, so building the RoT without a real
    // region/credentials is fine — the AWS SDK validates the region string but doesn't make a
    // network call here.
    val hocon = """
      aegis.crypto {
        kind = "aws-kms"
        aws-kms {
          region  = "us-east-1"
          kek-arn = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
        }
      }
    """
    val rot   = invoke(cfg(hocon)).use(IO.pure).unsafeRunSync()
    rot shouldBe a[AwsKmsRootOfTrust]
  }

  test("kind=aws-kms with missing region fails at boot (no silent fallback to dev)") {
    val hocon = """
      aegis.crypto {
        kind = "aws-kms"
        aws-kms {
          region  = ""
          kek-arn = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
        }
      }
    """
    val ex = intercept[IllegalArgumentException] {
      invoke(cfg(hocon)).use(IO.pure).unsafeRunSync()
    }
    ex.getMessage should include("aegis.crypto.aws-kms.region")
  }

  test("kind=aws-kms with missing kek-arn fails at boot (no silent fallback to dev)") {
    val hocon = """
      aegis.crypto {
        kind = "aws-kms"
        aws-kms {
          region  = "us-east-1"
          kek-arn = ""
        }
      }
    """
    val ex = intercept[IllegalArgumentException] {
      invoke(cfg(hocon)).use(IO.pure).unsafeRunSync()
    }
    ex.getMessage should include("aegis.crypto.aws-kms.kek-arn")
  }

  test("unknown kind fails fast with a clear error message") {
    val ex = intercept[IllegalArgumentException] {
      invoke(cfg("""aegis.crypto.kind = "softhsm" """)).use(IO.pure).unsafeRunSync()
    }
    ex.getMessage should include("Unknown aegis.crypto.kind=softhsm")
    ex.getMessage should include("'in-memory'")
    ex.getMessage should include("'aws-kms'")
  }
