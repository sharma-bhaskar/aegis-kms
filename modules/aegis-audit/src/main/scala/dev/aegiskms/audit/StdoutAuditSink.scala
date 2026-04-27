package dev.aegiskms.audit

import cats.effect.IO
import dev.aegiskms.core.Principal

/** A trivial sink that prints one structured line per record to STDOUT.
  *
  * Format mirrors the demo transcript in the README so an operator running `aegis-server` against the
  * in-memory journal sees output identical to what `aegis audit tail` will produce in PR C1:
  * {{{
  * 03:14:09Z  KeyUsed    actor=alice@org           parent=-                     key=invoice-2026  op=Create   outcome=Success
  * 03:14:53Z  KeyUsed    actor=claude-session-7a3  parent=alice@org             key=treasury     op=Sign     outcome=Failed code=PermissionDenied
  * }}}
  *
  * Used by the dev-mode server when no other sink is configured. Production setups should replace with the
  * Postgres sink (PR F2.b) plus a Kafka/SIEM fan-out (PR F2.c).
  */
final class StdoutAuditSink extends AuditSink[IO]:
  def write(record: AuditRecord): IO[Unit] = IO {
    val parentSubject = record.principal match
      case Principal.Agent(_, op, _, _, _, _, _) => op.subject
      case _                                     => "-"
    val ts = record.at.toString
    val actor = padTo(record.principal.subject, 22)
    val parent = padTo(parentSubject, 22)
    val resource = padTo(record.resource, 36)
    val op = padTo(record.operation.toString, 9)
    println(s"$ts  KeyOp     actor=$actor parent=$parent key=$resource op=$op outcome=${record.outcome}")
  }

  private def padTo(s: String, n: Int): String =
    if s.length >= n then s else s + (" " * (n - s.length))

object StdoutAuditSink:
  def apply(): StdoutAuditSink = new StdoutAuditSink
