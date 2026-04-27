package dev.aegiskms.iam

import cats.effect.IO
import dev.aegiskms.core.*

/** Decorator that consults a `PolicyEngine` before delegating to the underlying `KeyService`.
  *
  * On `Decision.Allow` the call passes through. On `Decision.Deny` the call short-circuits with
  * `KmsError(PermissionDenied, reason)` without ever touching the wrapped service.
  *
  * `Decision.StepUpRequired` is mapped to `PermissionDenied` for now — the real handling lands when we
  * introduce the step-up auth flow alongside OIDC + JWT issuance.
  *
  * Order of decoration: the audit decorator should wrap THIS, not the other way round. If
  * `AuthorizingKeyService` were the outer layer, denies would short-circuit before the audit decorator ever
  * ran, leaving denied attempts invisible to the audit log. Wired correctly (audit-outside-auth), denies
  * surface as `outcome=Failed code=PermissionDenied` records in the audit feed.
  */
final class AuthorizingKeyService(
    inner: KeyService[IO],
    engine: PolicyEngine[IO]
) extends KeyService[IO]:

  def create(spec: KeySpec, by: Principal): IO[Either[KmsError, ManagedKey]] =
    guard(by, Operation.Create, s"name:${spec.name}")(inner.create(spec, by))

  def get(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    guard(by, Operation.Get, id.value)(inner.get(id, by))

  def locate(namePattern: String, by: Principal): IO[List[ManagedKey]] =
    engine.permit(by, Operation.Locate, s"pattern:$namePattern").flatMap {
      case Decision.Allow            => inner.locate(namePattern, by)
      case Decision.Deny(_)          => IO.pure(Nil)
      case Decision.StepUpRequired(_) => IO.pure(Nil)
    }

  def activate(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    guard(by, Operation.Activate, id.value)(inner.activate(id, by))

  def revoke(id: KeyId, by: Principal): IO[Either[KmsError, ManagedKey]] =
    guard(by, Operation.Revoke, id.value)(inner.revoke(id, by))

  def destroy(id: KeyId, by: Principal): IO[Either[KmsError, Unit]] =
    guard(by, Operation.Destroy, id.value)(inner.destroy(id, by))

  private def guard[A](by: Principal, op: Operation, resource: String)(
      action: => IO[Either[KmsError, A]]
  ): IO[Either[KmsError, A]] =
    engine.permit(by, op, resource).flatMap {
      case Decision.Allow              => action
      case Decision.Deny(reason)       => IO.pure(Left(KmsError(ErrorCode.PermissionDenied, reason)))
      case Decision.StepUpRequired(why) =>
        IO.pure(Left(KmsError(ErrorCode.PermissionDenied, s"step-up required: $why")))
    }
